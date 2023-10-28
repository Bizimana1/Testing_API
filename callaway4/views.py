from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from django.contrib.auth.models import User
from .serializers import UserSerializer
from API.models import Profile_Pictures
from django.http import JsonResponse

class RegisterView(APIView):
    permission_classes = (permissions.AllowAny, )

    def post(self, request):
        try:
            data = request.data

            first_name = data['first_name']
            last_name = data['last_name']
            username = data['username']
            password = data['password']
            re_passsword = data['re_passsword']

            if password == re_passsword:
                if len(password) >= 8:
                    if not User.objects.filter(username=username).exists():
                        user = User.objects.create_user(
                            first_name=first_name,
                            last_name=last_name,
                            username=username,
                            password=password,
                        )

                        user.save()

                        if User.objects.filter(username=username).exists():
                            return Response(
                                {'success': 'Account created successfully'},
                                status=status.HTTP_201_CREATED
                            )

                        else:
                            return Response(
                                {'error': 'Account not created'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR
                            )

                    else:
                        return Response(
                            {'error': 'Username already exists'},
                            status=status.HTTP_400_BAD_REQUEST
                        )

            else:
                return Response(
                    {'error': 'Passwords do not match'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        except:
            return Response(
                {'error': 'Error, something went wrong'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LoadUserView(APIView):
    def get(self, request, format=None):
        try:
            user = request.user
            user = UserSerializer(user)

            return Response(
                {'user': user.data},
                status=status.HTTP_200_OK
            )
        
        except:
            return Response(
                {'error': 'cannot load user'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
class User_Profile(APIView):
    def get(self,request,username):
        profile=[]
        try:
            user_id=User.objects.get(username=username).id
            userProfile=Profile_Pictures.objects.get(user_id=user_id).img
            profile.append({'img':userProfile.url})
        except :
            userProfile=Profile_Pictures.objects.get(user_id=0000).img
            profile.append({'img':userProfile.url})
        return JsonResponse(profile,safe=False)



#for testing

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.contrib.sessions.backends.db import SessionStore

session = SessionStore()
session_key = session.session_key
from django.http import JsonResponse
class TokenView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, format=None):
        print("user:",request.user)
        refresh = RefreshToken.for_user(request.user)

        # session_key = session.session_key

        session = SessionStore(session_key=session_key)

        # Access the session value with key "key1"
        value = session.get("key1")

        print("token: ",value)
        return Response({
            'access': session.get("key1")
        })

    def post(self, request, format=None):
        username = request.data['username']#"salomon"
        password = request.data['password']#"12345"

        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                print("user:",user)
                refresh = RefreshToken.for_user(user)
                # session.headers['Authorization'] = f'Bearer {str(refresh.access_token)}'
                request.session['access_token'] = str(refresh.access_token)
                session['key1'] =str(refresh.access_token)
                session.save()

                # print("token: ",session['key1'])
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
                
            else:
                return Response({'error': 'Invalid password'}, status=400)
        except User.DoesNotExist:
            return Response({'error': 'Invalid username'}, status=400)


from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

        

class MyViewSet(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated   ]

    def get(self, request):
                # Token is present and not empty
                # Perform the action when the token is not empty
                data = [{"name": "salomon", "age": 25}]
                # data.append(1)
                print("user1:",request.user.username)
                return JsonResponse(data, safe=False)
        #     else:
        #         # Token is empty or not present
        #         # Handle the case when the token is empty or missing
        #         # ...
        #         return JsonResponse({"message": "login to generate a token"})
        # else:
        #     # Token is empty or not present
        #     # Handle the case when the token is empty or missing
        #     # ...
        #     return JsonResponse({"message": "Unauthorized"})
        # # return JsonResponse({"message": "Unauthorized"})




def set_session_data(request, key, value):
    # Set session data
    request.session[key] = value

    # Save the session data
    request.session.save()

def display_session_data(request):
    # Retrieve session data
    session_data = dict(request.session)

    # Display session data
    for key, value in session_data.items():
        print(f"{key}: {value}")




from django.contrib.auth.views import LoginView
from django.contrib.auth import login
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated




from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login
from django.middleware.csrf import get_token
from App.middleware import CustomCsrfMiddleware
from django.core.cache import cache
from django.contrib.auth import logout
from API.models import Profile_Pictures

def login_view(request):
    # print(request.method)   
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print("user:", request.POST)    
        # remember_me = request.POST.get('remember_me')
        # next_url = request.POST.get('next')

        # Check if authentication result is already cached
        cache_key = f"auth_result:{username}:{password}"
        user = cache.get(cache_key)

        if user is None:
            # If not cached, authenticate user and cache the result
            user = authenticate(request, username=username, password=password)
            cache.set(cache_key, user)

        if user is not None:
            if user.is_active:
                login(request, user)
                print("user1:",request.user.username)
                

                return JsonResponse({'message': 'success'}, status=200)
            else:
                error_message = 'Your account is not active'
        else:
            # print("user3:",request.user.username)
            error_message = 'Invalid login credentials'

        return JsonResponse({'message': error_message},status=400)

    # print("user1:",request.user.username)
    return JsonResponse({'message': 'try to login'})

def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'logout success'})



def ProtectedView(request):
    user = request.user.username
    print(user)
    return JsonResponse({'message': f'Hello, {user}!'})


class Profile(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user=request.user.username
        
        try:
            profile=Profile_Pictures.objects.get(user_id=request.user.id)
            img= profile.img.url
            
            # return request.session['profile']
            # print(" try :user name=",user)
            return JsonResponse({'profile': img,'user_name':user})
        except:
            profile=Profile_Pictures.objects.get(user_id='0000')
            img=profile.img.url
            # return request.session['profile']
            # print("except :user name=",user)
            return JsonResponse({'profile': img,'user_name':user})
    
