from django.contrib import admin
from django.urls import path
from smart_community import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/store/', views.store_data, name='store_data'),
    path('api/verify/<int:id>/', views.verify_data, name='verify_data'),
]