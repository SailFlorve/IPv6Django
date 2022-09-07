"""IPv6Django URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include

from IPv6Django import views
from IPv6Django.views_rest import IPv6TaskAPIView, IPv6TaskIdAPIView

api_url = [
    url(r'^$', IPv6TaskAPIView.as_view(), name='generic_task'),  # 集合操作
    url(r'/(?P<pk>\S*)$', IPv6TaskIdAPIView.as_view(), name='detail_task'),  # 访问某个特定对象
]

api_v1 = [url('^ipv6_task', include(api_url))]  # API 的 v1 版本
api_versions = [url(r'^v1/', include(api_v1))]

urlpatterns = [
    path('admin/', admin.site.urls),
    path('ipv6_generate/', views.upload_ipv6_generate),
    path('get_task_ids/', views.get_task_ids),
    path('get_task_state/', views.get_task_state),
    path('get_task_result/', views.get_task_result),
    path('terminate_task/', views.terminate_task),
    path('vulnerability_scan/', views.vulnerability_scan),
    path('get_log/', views.get_log),
    url(r'^api/', include(api_versions)),
]

print(IPv6TaskAPIView.as_view())
