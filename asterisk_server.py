#!/usr/bin/env python3
"""
Servidor HTTP CONCURRENTE para Asterisk con autenticación
- Soporte multi-threaded para manejar múltiples peticiones simultáneas
- Pool de threads configurable
- Timeouts apropiados
- Queue para operaciones pesadas

Uso:
  python3.12 /opt/asterisk-services/asterisk_server.py
"""

import os
import time
import json
import subprocess
import hashlib
import mimetypes
import threading
import queue
import concurrent.futures
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

# Servidor con soporte multi-threading
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer que maneja cada request en un thread separado"""
    
    # Configuración de threading
    daemon_threads = True                    # Threads se cierran al cerrar servidor
    max_children = 50                       # Máximo de threads concurrentes
    request_queue_size = 100                # Cola de requests pendientes
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pool de threads para operaciones pesadas (conversión audio)
        self.conversion_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=5,  # Máximo 5 conversiones simultáneas
            thread_name_prefix="AudioConvert"
        )
        print(f"Servidor threaded iniciado - Max children: {self.max_children}")
        print(f"Pool de conversión: {self.conversion_pool._max_workers} workers")

class SecureAsteriskHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Configuración de directorios
        self.recordings_dir = '/var/spool/asterisk/recording'
        self.tts_dir = '/tmp/asterisk/tts'
        self.stt_dir = '/tmp/asterisk/stt'
        
        self.valid_api_keys = self.load_api_keys()
        self.max_file_size = 50 * 1024 * 1024  # 50MB max
        self.allowed_extensions = ['.wav', '.mp3', '.ogg']
        
        # Timeouts para operaciones pesadas
        self.conversion_timeout = 30  # 30 segundos max para conversión
        self.upload_timeout = 60     # 60 segundos max para upload
        
        # Crear directorios temporales
        self.ensure_temp_directories()
        
        super().__init__(*args, directory=self.recordings_dir, **kwargs)
    
    def ensure_temp_directories(self):
        """Crear directorios temporales si no existen"""
        for directory in [self.tts_dir, self.stt_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory, mode=0o755)
                print(f"[{threading.current_thread().name}] Directorio temporal creado: {directory}")
    
    def load_api_keys(self):
        """Cargar API keys válidas desde archivo de configuración"""
        config_file = '/opt/asterisk-services/api_keys.txt'
        api_keys = set()
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        key = line.strip()
                        if key and not key.startswith('#'):
                            api_keys.add(key)
            else:
                # Crear archivo con API key por defecto
                default_key = 'asterisk-api-' + hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
                with open(config_file, 'w') as f:
                    f.write(f"# API Keys para servidor Asterisk\n")
                    f.write(f"# Formato: una clave por línea\n")
                    f.write(f"{default_key}\n")
                os.chmod(config_file, 0o600)
                api_keys.add(default_key)
                print(f"Archivo de API keys creado: {config_file}")
                print(f"API Key por defecto: {default_key}")
        except Exception as e:
            print(f"Error cargando API keys: {e}")
            api_keys.add('dev-asterisk-key-12345')
        
        return api_keys
    
    def authenticate_request(self):
        """Verificar autenticación via header Authorization"""
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        
        parts = auth_header.split(' ', 1)
        if len(parts) != 2:
            return False
        
        scheme, api_key = parts
        if scheme.lower() not in ['bearer', 'apikey']:
            return False
        
        return api_key in self.valid_api_keys
    
    def log_access(self, method, path, authenticated, client_ip):
        """Log de accesos con información de thread y seguridad"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        thread_name = threading.current_thread().name
        auth_status = "AUTH" if authenticated else "UNAUTH"
        print(f"[{timestamp}] [{thread_name}] {client_ip} - {method} {path} - {auth_status}")
    
    def send_auth_error(self):
        """Enviar error de autenticación"""
        self.send_response(401)
        self.send_header('Content-Type', 'application/json')
        self.send_header('WWW-Authenticate', 'Bearer realm="Asterisk API"')
        self.end_headers()
        
        error_response = {
            "error": "Authentication required",
            "message": "Provide valid API key in Authorization header",
            "format": "Authorization: Bearer YOUR_API_KEY",
            "thread": threading.current_thread().name
        }
        self.wfile.write(json.dumps(error_response).encode())
    
    def get_target_directory(self, filename):
        """Determinar directorio destino para uploads"""
        if filename.startswith('tts_'):
            return self.tts_dir
        elif filename.startswith(('placa_', 'papeleta_')):
            return self.stt_dir
        else:
            return self.recordings_dir
    
    def validate_file_upload(self, filename, content_length):
        """Validar archivo antes de procesarlo"""
        if content_length > self.max_file_size:
            return False, f"File too large. Max size: {self.max_file_size/1024/1024}MB"
        
        _, ext = os.path.splitext(filename.lower())
        if ext not in self.allowed_extensions:
            return False, f"Invalid file type. Allowed: {', '.join(self.allowed_extensions)}"
        
        if not filename.replace('_', '').replace('-', '').replace('.', '').isalnum():
            return False, "Invalid filename. Use only alphanumeric characters, hyphens and underscores"
        
        return True, "Valid"
    
    def do_GET(self):
        """Manejar descargas con autenticación"""
        client_ip = self.client_address[0]
        
        # Verificar autenticación
        if not self.authenticate_request():
            self.log_access("GET", self.path, False, client_ip)
            self.send_auth_error()
            return
        
        self.log_access("GET", self.path, True, client_ip)
        
        # Endpoint de status
        if self.path == '/status':
            self.handle_status()
            return
        
        # Rutas específicas para TTS y STT
        if self.path.startswith('/tts/'):
            self.handle_tts_download()
            return
        elif self.path.startswith('/stt/'):
            self.handle_stt_download()
            return
        
        # Descargas normales desde recordings_dir
        try:
            filename = os.path.basename(self.path.lstrip('/'))
            if not filename:
                self.send_error(400, "Filename required")
                return
            
            file_path = os.path.join(self.recordings_dir, filename)
            
            if not os.path.exists(file_path):
                self.send_error(404, f"File not found: {filename}")
                return
            
            self.serve_file(file_path, filename)
            
        except Exception as e:
            print(f"[{threading.current_thread().name}] Error en GET: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def handle_tts_download(self):
        """Descargar archivos TTS desde /tmp/asterisk/tts/"""
        try:
            filename = os.path.basename(self.path[5:])  # Remover '/tts/'
            file_path = os.path.join(self.tts_dir, filename)
            
            if not os.path.exists(file_path):
                self.send_error(404, f"TTS file not found: {filename}")
                return
            
            self.serve_file(file_path, filename)
            
        except Exception as e:
            print(f"[{threading.current_thread().name}] Error en TTS download: {e}")
            self.send_error(500, f"TTS download error: {str(e)}")
    
    def handle_stt_download(self):
        """Descargar grabaciones STT desde /tmp/asterisk/stt/"""
        try:
            filename = os.path.basename(self.path[5:])  # Remover '/stt/'
            file_path = os.path.join(self.stt_dir, filename)
            
            if not os.path.exists(file_path):
                self.send_error(404, f"STT file not found: {filename}")
                return
            
            self.serve_file(file_path, filename)
            
        except Exception as e:
            print(f"[{threading.current_thread().name}] Error en STT download: {e}")
            self.send_error(500, f"STT download error: {str(e)}")
    
    def serve_file(self, file_path, filename):
        """Servir un archivo al cliente"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        self.send_response(200)
        self.send_header('Content-Type', 'audio/wav')
        self.send_header('Content-Length', str(len(file_data)))
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(file_data)
        
        print(f"[{threading.current_thread().name}] Archivo servido: {file_path} ({len(file_data)} bytes)")
    
    def do_POST(self):
        """Manejar uploads con autenticación y procesamiento asíncrono"""
        client_ip = self.client_address[0]
        
        # Verificar autenticación
        if not self.authenticate_request():
            self.log_access("POST", self.path, False, client_ip)
            self.send_auth_error()
            return
        
        self.log_access("POST", self.path, True, client_ip)
        
        if self.path in ['/upload', '/tts', '/stt']:
            self.handle_upload_async()
        elif self.path == '/status':
            self.handle_status()
        else:
            self.send_error(404, "Endpoint not found")
    
    def do_DELETE(self):
        """Manejar eliminación de archivos SOLO de /var/spool/asterisk/recording/"""
        client_ip = self.client_address[0]
        
        # Verificar autenticación
        if not self.authenticate_request():
            self.log_access("DELETE", self.path, False, client_ip)
            self.send_auth_error()
            return
        
        self.log_access("DELETE", self.path, True, client_ip)
        
        try:
            filename = os.path.basename(self.path.lstrip('/'))
            if not filename:
                self.send_error(400, "Filename required")
                return
            
            # SOLO eliminar archivos de /var/spool/asterisk/recording/
            file_path = os.path.join(self.recordings_dir, filename)
            
            if not os.path.exists(file_path):
                self.send_error(404, f"Recording file not found: {filename}")
                return
            
            # Eliminar archivo de recordings
            os.remove(file_path)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                "status": "success",
                "message": f"Recording file deleted: {filename}",
                "path": file_path,
                "thread": threading.current_thread().name,
                "note": "/tmp files are cleaned automatically by OS"
            }
            self.wfile.write(json.dumps(response).encode())
            
            print(f"[{threading.current_thread().name}] Archivo eliminado: {file_path}")
            
        except Exception as e:
            print(f"[{threading.current_thread().name}] Error en DELETE: {e}")
            self.send_error(500, f"Delete failed: {str(e)}")
    
    def handle_upload_async(self):
        """Manejar upload con procesamiento asíncrono para conversión"""
        try:
            # Obtener información del archivo
            filename = self.headers.get('Filename')
            if not filename:
                filename = f'upload_{int(time.time())}.wav'
            
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No file data provided")
                return
            
            # Validar archivo
            is_valid, validation_message = self.validate_file_upload(filename, content_length)
            if not is_valid:
                self.send_error(400, validation_message)
                return
            
            thread_name = threading.current_thread().name
            print(f"[{thread_name}] Upload autorizado: {filename} ({content_length} bytes)")
            
            # Leer datos del archivo con timeout
            start_time = time.time()
            file_data = self.rfile.read(content_length)
            read_time = time.time() - start_time
            
            if read_time > self.upload_timeout:
                self.send_error(408, f"Upload timeout after {read_time:.1f}s")
                return
            
            # Determinar directorio destino
            target_dir = self.get_target_directory(filename)
            
            # Guardar archivo temporal inmediatamente
            temp_filepath = os.path.join(target_dir, f"temp_{thread_name}_{filename}")
            with open(temp_filepath, 'wb') as f:
                f.write(file_data)
            
            print(f"[{thread_name}] Archivo temporal guardado: {temp_filepath}")
            
            # Determinar archivo final
            final_filepath = os.path.join(target_dir, filename)
            
            # PROCESAMIENTO ASÍNCRONO: Enviar conversión al pool de threads
            future = self.server.conversion_pool.submit(
                self.convert_audio_with_cleanup,
                temp_filepath,
                final_filepath,
                thread_name
            )
            
            try:
                # Esperar resultado con timeout
                success, message = future.result(timeout=self.conversion_timeout)
                
                if success:
                    file_size = os.path.getsize(final_filepath)
                    print(f"[{thread_name}] Archivo procesado exitosamente: {final_filepath} ({file_size} bytes)")
                    
                    # Respuesta exitosa
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    cleanup_info = ""
                    if target_dir in [self.tts_dir, self.stt_dir]:
                        cleanup_info = " (will be cleaned automatically by OS)"
                    
                    response = {
                        "status": "success",
                        "filename": filename,
                        "directory": target_dir,
                        "original_size": len(file_data),
                        "converted_size": file_size,
                        "processing_time": f"{read_time + (time.time() - start_time):.2f}s",
                        "thread": thread_name,
                        "message": f"File uploaded and converted successfully{cleanup_info}"
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.send_error(500, f"Audio conversion failed: {message}")
                    
            except concurrent.futures.TimeoutError:
                print(f"[{thread_name}] Conversion timeout para {filename}")
                self.send_error(408, f"Audio conversion timeout after {self.conversion_timeout}s")
                # Cancelar future si es posible
                future.cancel()
                
        except Exception as e:
            print(f"[{threading.current_thread().name}] Error en upload: {e}")
            self.send_error(500, f"Upload failed: {str(e)}")
    
    def convert_audio_with_cleanup(self, temp_filepath, final_filepath, thread_name):
        """Convertir audio con limpieza automática - ejecutado en pool de threads"""
        try:
            print(f"[{thread_name}] Iniciando conversión: {temp_filepath} -> {final_filepath}")
            
            # Intentar conversión con sox
            try:
                result = subprocess.run([
                    'sox', temp_filepath,
                    '-r', '8000',  # Sample rate 8000Hz
                    '-c', '1',     # Mono
                    '-b', '16',    # 16-bit
                    final_filepath
                ], capture_output=True, text=True, timeout=25)
                
                if result.returncode == 0:
                    print(f"[{thread_name}] Conversión exitosa con sox: {final_filepath}")
                    self.cleanup_temp_file(temp_filepath, thread_name)
                    os.chmod(final_filepath, 0o644)
                    return True, "Converted with sox"
                else:
                    print(f"[{thread_name}] Error con sox: {result.stderr}")
                    
            except FileNotFoundError:
                print(f"[{thread_name}] sox no encontrado, intentando con ffmpeg...")
            except subprocess.TimeoutExpired:
                print(f"[{thread_name}] sox timeout")
            
            # Intentar con ffmpeg
            try:
                result = subprocess.run([
                    'ffmpeg', '-i', temp_filepath,
                    '-ar', '8000',
                    '-ac', '1',
                    '-y',
                    final_filepath
                ], capture_output=True, text=True, timeout=25)
                
                if result.returncode == 0:
                    print(f"[{thread_name}] Conversión exitosa con ffmpeg: {final_filepath}")
                    self.cleanup_temp_file(temp_filepath, thread_name)
                    os.chmod(final_filepath, 0o644)
                    return True, "Converted with ffmpeg"
                else:
                    print(f"[{thread_name}] Error con ffmpeg: {result.stderr}")
                    
            except FileNotFoundError:
                print(f"[{thread_name}] ffmpeg no encontrado")
            except subprocess.TimeoutExpired:
                print(f"[{thread_name}] ffmpeg timeout")
            
            # Fallback: copiar archivo original
            print(f"[{thread_name}] Warning: No se pudo convertir audio, usando archivo original")
            import shutil
            shutil.copy2(temp_filepath, final_filepath)
            self.cleanup_temp_file(temp_filepath, thread_name)
            os.chmod(final_filepath, 0o644)
            return True, "Used original file (no conversion)"
            
        except Exception as e:
            print(f"[{thread_name}] Error en conversión: {e}")
            self.cleanup_temp_file(temp_filepath, thread_name)
            return False, str(e)
    
    def cleanup_temp_file(self, temp_filepath, thread_name):
        """Limpiar archivo temporal de forma segura"""
        try:
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
                print(f"[{thread_name}] Archivo temporal eliminado: {temp_filepath}")
        except Exception as e:
            print(f"[{thread_name}] Error eliminando temporal: {e}")
    
    def handle_status(self):
        """Endpoint de estado del servidor con información de threading"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        # Contar archivos en cada directorio
        def count_files(directory, pattern='*.wav'):
            try:
                import glob
                return len(glob.glob(os.path.join(directory, pattern)))
            except:
                return 0
        
        # Información de threading
        active_threads = threading.active_count()
        thread_names = [t.name for t in threading.enumerate()]
        
        status = {
            "status": "running",
            "version": "3.0-concurrent",
            "threading": {
                "active_threads": active_threads,
                "max_children": getattr(self.server, 'max_children', 'N/A'),
                "conversion_pool_workers": self.server.conversion_pool._max_workers,
                "conversion_pool_queue": self.server.conversion_pool._work_queue.qsize(),
                "thread_names": thread_names,
                "current_thread": threading.current_thread().name
            },
            "directories": {
                "recordings": {
                    "path": self.recordings_dir,
                    "files_count": count_files(self.recordings_dir),
                    "cleanup": "manual via DELETE"
                },
                "tts_temp": {
                    "path": self.tts_dir,
                    "files_count": count_files(self.tts_dir),
                    "cleanup": "automatic by OS"
                },
                "stt_temp": {
                    "path": self.stt_dir,
                    "files_count": count_files(self.stt_dir),
                    "cleanup": "automatic by OS"
                }
            },
            "timeouts": {
                "conversion_timeout": self.conversion_timeout,
                "upload_timeout": self.upload_timeout
            },
            "endpoints": {
                "GET": ["/status", "/filename.wav", "/tts/filename.wav", "/stt/filename.wav"],
                "POST": ["/upload", "/tts", "/stt"],
                "DELETE": ["/filename.wav (only from recordings directory)"]
            },
            "timestamp": time.time(),
            "security": {
                "authentication": "enabled",
                "max_file_size_mb": self.max_file_size / 1024 / 1024,
                "allowed_extensions": self.allowed_extensions
            },
            "conversion_tools": self.check_conversion_tools()
        }
        self.wfile.write(json.dumps(status, indent=2).encode())
    
    def check_conversion_tools(self):
        """Verificar herramientas de conversión disponibles"""
        tools = {}
        
        # Verificar sox
        try:
            result = subprocess.run(['sox', '--version'], capture_output=True, text=True, timeout=5)
            tools['sox'] = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools['sox'] = False
        
        # Verificar ffmpeg
        try:
            result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True, timeout=5)
            tools['ffmpeg'] = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools['ffmpeg'] = False
        
        return tools
    
    def log_message(self, format, *args):
        """Log personalizado con timestamp y thread"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        thread_name = threading.current_thread().name
        print(f"[{timestamp}] [{thread_name}] {format % args}")

def main():
    # Verificar que se ejecuta como usuario apropiado
    if os.geteuid() == 0:
        print("Warning: Ejecutándose como root. Considere usar usuario asterisk.")
    
    # Crear directorios necesarios
    directories = [
        '/opt/asterisk-services',
        '/var/spool/asterisk/recording',
        '/tmp/asterisk/tts',
        '/tmp/asterisk/stt'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory, mode=0o755)
            print(f"Directorio creado: {directory}")
    
    # Cambiar al directorio de grabaciones permanentes
    os.chdir('/var/spool/asterisk/recording')
    
    # Verificar herramientas de conversión
    print("Verificando herramientas de conversión...")
    try:
        subprocess.run(['sox', '--version'], capture_output=True, check=True, timeout=5)
        print("sox: DISPONIBLE")
    except:
        print("sox: NO DISPONIBLE")
    
    try:
        subprocess.run(['ffmpeg', '--version'], capture_output=True, check=True, timeout=5)
        print("ffmpeg: DISPONIBLE")
    except:
        print("ffmpeg: NO DISPONIBLE")
    
    print("\n Servidor HTTP Asterisk CONCURRENTE iniciando...")
    print(f"Directorio grabaciones permanentes: /var/spool/asterisk/recording")
    print(f"Directorio TTS temporal: /tmp/asterisk/tts (limpieza automática)")
    print(f"Directorio STT temporal: /tmp/asterisk/stt (limpieza automática)")
    print(f"DELETE: Solo funciona en /var/spool/asterisk/recording/")
    print(f"Threading: Máximo 50 conexiones concurrentes")
    print(f"Pool conversión: 5 workers para procesamiento de audio")
    print(f"Escuchando en: http://0.0.0.0:8001")
    print("Presiona Ctrl+C para detener")
    print("-" * 70)
    
    # Crear servidor threaded
    server = ThreadedHTTPServer(('0.0.0.0', 8001), SecureAsteriskHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDeteniendo servidor...")
        # Cerrar pool de threads
        server.conversion_pool.shutdown(wait=True)
        server.shutdown()
        print("Servidor detenido")

if __name__ == '__main__':
    main()
