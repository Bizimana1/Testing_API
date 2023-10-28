from django.urls import path
# from .views import RegisterView, LoadUserView,User_Profile
from .views import *
urlpatterns = [
    path('register', RegisterView.as_view()),
    path('user', LoadUserView.as_view()),
    path('User_Profile/<str:username>',User_Profile.as_view()),

     path('myview/',MyViewSet.as_view(),name="view"),
    path('token/', TokenView.as_view(), name='custom_token_obtain'),

       path('profile/', Profile.as_view(), name='profile'),
      path('login/', login_view, name='login'),
      path('logout/', logout_view, name='logout'),
      path('protected/', ProtectedView, name='protected'),

    
    # ...
]