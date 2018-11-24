from django.conf.urls import url, include,re_path
from .views import *
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [

        re_path(r'^auth/check/email/?$', AuthView.as_view({'post': 'check_email'})),
        re_path(r'^auth/check/username/?$', AuthView.as_view({'post': 'check_username'})),
        re_path(r'^auth/signup/?$',AuthView.as_view({'post': 'signup'})),
        re_path(r'^auth/login/?$',AuthView.as_view({'post': 'login'})),
        re_path(r'^auth/generate/code/?$',AuthView.as_view({'post': 'generate_code'})),
        re_path(r'^auth/verify/code/?$',AuthView.as_view({'post': 'verify_code'})),
        re_path(r'^auth/reset/password/?$',AuthView.as_view({'post': 'reset_password'})),
        re_path(r'^events/?$', EventsView.as_view({'get': 'get_all_events'})),
        # re_path(r'^auth/login/?$',HashAuthToken.as_view(), name='login'),
        # re_path(r'^users/login/?$',UserView.as_view(), name='login'),
        # re_path(r'^user/login/?$',UserView.as_view(), name='login'),
        # re_path(r'^user/login/?$',UserView.as_view(), name='login'),
        # re_path(r'^user/login/?$',UserView.as_view(), name='login'),



]
