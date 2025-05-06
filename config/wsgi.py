# config/wsgi.py 或 smart_community/wsgi.py
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')  # 确保与你的项目名一致
application = get_wsgi_application()  # 这行必须存在！