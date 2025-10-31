# accounts/views.py
from firebase_admin import auth as firebase_auth
import uuid
import random
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.middleware.csrf import get_token
import json
import datetime
from django.contrib.auth.hashers import check_password
Usuario = get_user_model()

def generar_codigo():
    return str(random.randint(100000, 999999))

@ensure_csrf_cookie
def get_csrf_token(request):
    """
    Endpoint para que Angular obtenga el CSRF token
    """
    return JsonResponse({'csrfToken': get_token(request)})

@csrf_exempt
def register_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    # Validar campos requeridos
    campos = ['nombre', 'apellidopaterno', 'apellidomaterno', 'username',
              'correo', 'contrasena', 'telefono', 'preguntasecreta', 'respuestasecreta']
    for c in campos:
        if not data.get(c):
            return JsonResponse({'error': f'El campo {c} es obligatorio'}, status=400)

    # Verificar unicidad
    if Usuario.objects.filter(username=data['username']).exists():
        return JsonResponse({'error': 'El nombre de usuario ya está en uso'}, status=400)
    if Usuario.objects.filter(email=data['correo']).exists():
        return JsonResponse({'error': 'El correo ya está registrado'}, status=400)
    if Usuario.objects.filter(telefono=data['telefono']).exists():
        return JsonResponse({'error': 'El teléfono ya está registrado'}, status=400)

    # Crear usuario
    usuario = Usuario(
        username=data['username'],
        email=data['correo'],
        first_name=data['nombre'],
        last_name=data['apellidopaterno'],
        telefono=data['telefono'],
        pregunta_secreta=data['preguntasecreta'],
        respuesta_secreta=data['respuestasecreta'],
        verificado=False,
    )
    usuario.set_password(data['contrasena'])
    usuario.save()

    # Generar y enviar código 2FA
    codigo = generar_codigo()
    temp_token = str(uuid.uuid4())
    request.session[temp_token] = {
        'email': data['correo'],
        'codigo': codigo,
        'intentos': 0,
        'expira': (datetime.datetime.now() + datetime.timedelta(minutes=5)).timestamp()
    }

    try:
        send_mail(
            'Código de verificación',
            f'Tu código es: {codigo}. Expira en 5 minutos.',
            settings.DEFAULT_FROM_EMAIL,
            [data['correo']],
            fail_silently=False,
        )
    except Exception as e:
        return JsonResponse({'error': 'No se pudo enviar el correo'}, status=500)

    return JsonResponse({
        'mensaje': 'Usuario registrado con éxito',
        'requires2fa': True,
        'canal': 'email',
        'destino': f"{data['correo'][:2]}***@{data['correo'].split('@')[1]}",
        'tempToken': temp_token,
    }, status=201)
@csrf_exempt
def verificar_registro_2fa(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
        temp_token = data.get('tempToken')
        codigo = data.get('codigo')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Datos inválidos'}, status=400)

    if not temp_token or not codigo:
        return JsonResponse({'error': 'tempToken y codigo son requeridos'}, status=400)

    # Obtener datos de la sesión
    session_data = request.session.get(temp_token)
    if not session_data:
        return JsonResponse({'error': 'Sesión 2FA inválida'}, status=400)

    # Verificar expiración (5 minutos)
    if datetime.datetime.now().timestamp() > session_data.get('expira', 0):
        del request.session[temp_token]
        return JsonResponse({'error': 'Código expirado. Solicita uno nuevo'}, status=400)

    # Verificar código
    if session_data['codigo'] != str(codigo):
        session_data['intentos'] = session_data.get('intentos', 0) + 1
        request.session[temp_token] = session_data  # Guardar intentos

        if session_data['intentos'] >= 5:
            del request.session[temp_token]
            return JsonResponse({'error': 'Demasiados intentos'}, status=429)

        return JsonResponse({'error': 'Código incorrecto'}, status=400)

    # Código correcto: marcar usuario como verificado
    try:
        usuario = Usuario.objects.get(email=session_data['email'])
        usuario.verificado = True
        usuario.save()
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=400)

    # Limpiar sesión
    del request.session[temp_token]

    return JsonResponse({'ok': True, 'mensaje': 'Verificación exitosa'})
@csrf_exempt
def login_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Datos inválidos'}, status=400)

    if not email or not password:
        return JsonResponse({'error': 'Email y contraseña son requeridos'}, status=400)

    # Autenticar usuario
    try:
        usuario = Usuario.objects.get(email=email)
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Credenciales inválidas'}, status=400)

    if not usuario.check_password(password):
        return JsonResponse({'error': 'Credenciales inválidas'}, status=400)

    # Si el usuario está verificado, requiere 2FA
    if usuario.verificado:
        codigo = generar_codigo()
        temp_token = str(uuid.uuid4())
        request.session[temp_token] = {
            'email': usuario.email,
            'codigo': codigo,
            'intentos': 0,
            'expira': (datetime.datetime.now() + datetime.timedelta(minutes=5)).timestamp()
        }

        try:
            send_mail(
                'Código de verificación',
                f'Tu código es: {codigo}. Expira en 5 minutos.',
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
                fail_silently=False,
            )
        except Exception:
            return JsonResponse({'error': 'No se pudo enviar el correo'}, status=500)

        return JsonResponse({
            'requires2fa': True,
            'tempToken': temp_token,
            'canal': 'email',
            'destino': f"{email[:2]}***@{email.split('@')[1]}",
        })

    # Si no está verificado, genera JWT (más adelante lo haremos)
    return JsonResponse({
        'ok': True,
        'mensaje': 'Inicio de sesión exitoso',
        'usuario': {
            'id': usuario.id,
            'email': usuario.email,
            'username': usuario.username,
        }
    })
@csrf_exempt
def verificar_login_2fa(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
        temp_token = data.get('tempToken')
        codigo = data.get('codigo')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Datos inválidos'}, status=400)

    if not temp_token or not codigo:
        return JsonResponse({'error': 'tempToken y codigo son requeridos'}, status=400)

    # Obtener datos de la sesión
    session_data = request.session.get(temp_token)
    if not session_data:
        return JsonResponse({'error': 'Sesión 2FA inválida'}, status=400)

    # Verificar expiración (5 minutos)
    if datetime.datetime.now().timestamp() > session_data.get('expira', 0):
        del request.session[temp_token]
        return JsonResponse({'error': 'Código expirado. Solicita uno nuevo'}, status=400)

    # Verificar código
    if session_data['codigo'] != str(codigo):
        session_data['intentos'] = session_data.get('intentos', 0) + 1
        request.session[temp_token] = session_data  # Guardar intentos

        if session_data['intentos'] >= 5:
            del request.session[temp_token]
            return JsonResponse({'error': 'Demasiados intentos'}, status=429)

        return JsonResponse({'error': 'Código incorrecto'}, status=400)

    # Código correcto: obtener usuario
    try:
        usuario = Usuario.objects.get(email=session_data['email'])
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=400)

    # Limpiar sesión
    del request.session[temp_token]

    # Aquí generarías un JWT en el futuro
    return JsonResponse({
        'ok': True,
        'mensaje': 'Inicio de sesión exitoso',
        'usuario': {
            'id': usuario.id,
            'email': usuario.email,
            'username': usuario.username,
        }
    })
@csrf_exempt
def google_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
        id_token = data.get('idToken')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Datos inválidos'}, status=400)

    if not id_token:
        return JsonResponse({'error': 'idToken es requerido'}, status=400)

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        email = decoded_token['email']
        name = decoded_token.get('name', '')

        # Buscar o crear usuario
        usuario, created = Usuario.objects.get_or_create(
            email=email,
            defaults={
                'username': email.split('@')[0] + '_' + str(uuid.uuid4())[:8],  # Evitar duplicados
                'first_name': name.split(' ')[0] if name else '',
                'last_name': name.split(' ')[1] if len(name.split(' ')) > 1 else '',
                'verificado': True,  # Google ya verifica el email
            }
        )

        return JsonResponse({
            'ok': True,
            'mensaje': 'Inicio de sesión con Google exitoso',
            'usuario': {
                'id': usuario.id,
                'email': usuario.email,
                'username': usuario.username,
            }
        })

    except Exception as e:
        # DEBUG: Mostrar el error completo en consola
        print("=" * 80)
        print("ERROR EN GOOGLE LOGIN:")
        print(f"Tipo de error: {type(e).__name__}")
        print(f"Mensaje de error: {str(e)}")
        import traceback
        print("Traceback completo:")
        traceback.print_exc()
        print("=" * 80)
        return JsonResponse({'error': f'Token de Google inválido: {str(e)}'}, status=401)
@csrf_exempt
def recuperar_contrasena(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get('email')
        pregunta_secreta = data.get('preguntaSecreta')
        respuesta_secreta = data.get('respuestaSecreta')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Datos inválidos'}, status=400)

    if not email or not pregunta_secreta or not respuesta_secreta:
        return JsonResponse({'error': 'Todos los campos son requeridos'}, status=400)

    try:
        usuario = Usuario.objects.get(email=email)
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=400)

    if usuario.pregunta_secreta != pregunta_secreta:
        return JsonResponse({'error': 'Pregunta secreta incorrecta'}, status=400)

    # Corregido: comparar respuesta secreta directamente (no está hasheada)
    if usuario.respuesta_secreta != respuesta_secreta:
        return JsonResponse({'error': 'Respuesta secreta incorrecta'}, status=400)

    # Generar token temporal
    temp_token = str(uuid.uuid4())
    request.session[temp_token] = {
        'email': usuario.email,
        'expira': (datetime.datetime.now() + datetime.timedelta(minutes=10)).timestamp(),
    }

    return JsonResponse({'ok': True, 'tempToken': temp_token})
@csrf_exempt
def restablecer_contrasena(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    try:
        data = json.loads(request.body)
        temp_token = data.get('tempToken')
        nueva_contrasena = data.get('nuevaContrasena')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Datos inválidos'}, status=400)

    if not temp_token or not nueva_contrasena:
        return JsonResponse({'error': 'tempToken y nuevaContrasena son requeridos'}, status=400)

    session_data = request.session.get(temp_token)
    if not session_data:
        return JsonResponse({'error': 'Token inválido o expirado'}, status=400)

    # Verificar expiración (10 minutos)
    if datetime.datetime.now().timestamp() > session_data['expira']:
        del request.session[temp_token]
        return JsonResponse({'error': 'Token expirado'}, status=400)

    try:
        usuario = Usuario.objects.get(email=session_data['email'])
        usuario.set_password(nueva_contrasena)
        usuario.save()
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=400)

    # Limpiar sesión
    del request.session[temp_token]

    return JsonResponse({'ok': True, 'mensaje': 'Contraseña actualizada con éxito'})