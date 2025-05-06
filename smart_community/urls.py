from django.contrib import admin
from django.urls import path
from smart_community import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('api/store/', views.store_data, name='store_data'),
    path('api/verify/<int:id>/', views.verify_data, name='verify_data'),
    path('api-docs/', views.api_docs, name='api_docs'),
]