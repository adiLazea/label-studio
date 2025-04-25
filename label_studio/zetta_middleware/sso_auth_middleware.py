from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from rest_framework.authtoken.models import Token
from organizations.models import Organization, OrganizationMember
from django.contrib import auth
import re, time
import jwt
import requests
from django.http import JsonResponse
from jwt import ExpiredSignatureError, InvalidTokenError
from django.conf import settings

class SSOMiddleware(MiddlewareMixin):
    STATIC_PATHS = [
        re.compile(r"^/static/"),
        re.compile(r"^/media/"),
        re.compile(r"^/favicon\.ico$"),
        re.compile(r"^/react-app/"),
        re.compile(r"^/__lsa/"),
        re.compile(r"^/heidi-tips/?$"),
    ]

    def get_or_create_user(self, email, username, roles):
        User = get_user_model()
        user, created = User.objects.get_or_create(email=email, defaults={"username": username})
        if created:
            user.is_active = True
            user.save()
        
        return user
    
    def setup_organization(self, user):
        if user and not user.active_organization:
            org, _ = Organization.objects.get_or_create(
                title="Default Organization",
                defaults={"created_by": user} 
            )
            
            if not org.created_by:
                org.created_by = user
                org.save(update_fields=["created_by"])

            # Ensure membership is set
            OrganizationMember.objects.get_or_create(user=user, organization=org)
            user.active_organization = org
            user.save(update_fields=["active_organization"])


    def get_keycloak_public_key(self):
        resp = requests.get(settings.KEYCLOAK_PUBLIC_KEY_URL, verify=False) #todo remove verify=False, once we have a valid ssl certificate(not a manually signed one)
        if resp.status_code != 200:
            raise Exception("Unable to fetch Keycloak public key")
        
        jwks = resp.json()
        for key in jwks["keys"]:
            if key["alg"] == "RS256":
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        
        raise Exception("Suitable public key not found")
    
    def extract_user_info(self, token):
        try:
            public_key = self.get_keycloak_public_key()
            decoded_token = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience="account",
                issuer=settings.KEYCLOAK_ISSUER
            )

            # Extract user info from the decoded token
            email = decoded_token.get('email')
            username = decoded_token.get('preferred_username')
            roles = decoded_token.get('realm_access', {}).get('roles', [])

            return username, email, roles
        except ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"Auth failed: {str(e)}"}, status=401)    


    def process_request(self, request):
        path = request.path
        if any(pattern.match(path) for pattern in self.STATIC_PATHS):
            return
        
        if request.user.is_authenticated:
            return
        
        token = request.META.get('HTTP_X_ACCESS_TOKEN')
        if not token:
            return redirect("/user/login/")

        username, email, roles = self.extract_user_info(token=token)
        user = self.get_or_create_user(email, username, roles)
        self.setup_organization(user=user)
        Token.objects.get_or_create(user=user)

        auth.login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        request.session['last_login'] = time.time()
        request.session.save()
        request.user = user
        
        return None
