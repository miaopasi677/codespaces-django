# GitHub Codespaces ♥️ Django

Welcome to your shiny new Codespace running Django! We've got everything fired up and running for you to explore Django.

You've got a blank canvas to work on from a git perspective as well. There's a single initial commit with what you're seeing right now - where you go from here is up to you!

Everything you do here is contained within this one codespace. There is no repository on GitHub yet. If and when you’re ready you can click "Publish Branch" and we’ll create your repository and push up your project. If you were just exploring then and have no further need for this code then you can simply delete your codespace and it's gone forever.

## installing dependancies

```python
pip install -r requirements.txt
```

## To collect static files:

```python
python manage.py collectstatic
```

## To run this application:

```python
python manage.py runserver
```
您想在 GitHub Codespaces 上重新构建“面向智慧社区的数据隐私保护及所有权验证方法”项目，基于 Django 环境，并直接修改 Codespaces 提供的默认 Django Hello World 代码，将其扩展为您的项目（包含 SM4 加密、以太坊区块链存证、RBAC 和审计日志功能）。以下是详细步骤，指导您如何在 GitHub Codespaces 中修改现有 Django 项目，重新构建您的智慧社区项目，运行多文件代码，并确保功能完整。我会结合您提供的项目文档，解决可能的配置问题（如私钥、路径、依赖），并考虑在 Codespaces 环境中的特殊性（如容器化、端口转发）。同时，我会保留与 Transformer 模型数据的潜在集成可能性。
背景与前提
GitHub Codespaces 是一个云端开发环境，提供预配置的容器（您选择了 Django 环境），默认包含 Python、Django 和一个 Hello World 示例（如 manage.py 和简单的 views.py）。
您的目标是将默认代码替换为智慧社区项目的功能，包含多文件结构（config/、smart_community/、contracts/ 等），并运行项目。
Codespaces 环境类似本地，但运行在 Docker 容器中，支持终端命令、VS Code 界面、端口转发（用于访问 http://127.0.0.1:8000）和持久化存储。
假设您已在 GitHub 仓库中创建了 Codespaces，并看到类似以下的默认结构：
.
├── manage.py
├── myproject/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
├── requirements.txt
步骤：在 GitHub Codespaces 重新构建项目
1. 初始化 Codespaces 环境
打开 Codespaces：
登录 GitHub，进入您的仓库。
点击 Code -> Codespaces -> Create Codespace on main（或已有 Codespace）。
选择 Django 环境（已预装 Python 和 Django）。
验证默认 Django 项目：
运行默认 Hello World 项目：
bash
python manage.py runserver
Codespaces 会提示端口转发链接（如 https://<your-codespace-name>.github.dev:8000）。
访问链接，确认看到 Django 的欢迎页面（“Congratulations!”）。
按 Ctrl+C 停止服务器。
清理默认代码：
保留 manage.py 和 requirements.txt，但替换 myproject/ 为您的项目结构。
删除默认的 myproject/：
bash
rm -rf myproject
2. 创建项目结构
在 Codespaces 终端或 VS Code 文件浏览器中，重建您的项目结构。
创建目录：
bash
mkdir config smart_community scripts contracts data docs
mkdir smart_community/encryption smart_community/audit smart_community/blockchain smart_community/permissions
touch config/__init__.py config/settings.py config/urls.py config/wsgi.py
touch smart_community/__init__.py smart_community/admin.py smart_community/apps.py smart_community/models.py smart_community/views.py
touch scripts/generate_data.py scripts/deploy_contract.py scripts/store_sample_data.py
touch contracts/DataStorage.sol
touch requirements.txt
最终结构：
.
├── config/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
├── smart_community/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── views.py
│   ├── encryption/
│   ├── audit/
│   ├── blockchain/
│   ├── permissions/
├── scripts/
│   ├── generate_data.py
│   ├── deploy_contract.py
│   ├── store_sample_data.py
├── contracts/
│   ├── DataStorage.sol
├── data/
├── docs/
├── manage.py
├── requirements.txt
3. 配置项目文件
基于您提供的项目文档，逐一创建和配置核心文件。
3.1 requirements.txt
text
django==4.2.11
gmssl==3.2.1
web3==6.11.0
py-solc-x==1.1.1
requests==2.31.0
安装依赖：
bash
pip install -r requirements.txt
3.2 config/settings.py
python
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'your-secret-key'  # 替换为安全密钥
DEBUG = True
ALLOWED_HOSTS = ['*']  # Codespaces 需允许所有主机

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'smart_community',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'data/db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

BLOCKCHAIN = {
    'PROVIDER': 'http://127.0.0.1:8545',
    'CONTRACT_ADDRESS': None,
    'PRIVATE_KEY': None,
}

ENCRYPTION = {
    'SM4_KEY': b'1234567890abcdef1234567890abcdef',  # 16 字节密钥
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'data/audit.log',
        },
    },
    'loggers': {
        'smart_community': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
3.3 config/urls.py
python
from django.contrib import admin
from django.urls import path
from smart_community import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/store/', views.store_data, name='store_data'),
    path('api/verify/<int:id>/', views.verify_data, name='verify_data'),
]
3.4 smart_community/models.py
python
from django.db import models
from django.contrib.auth.models import User

class CommunityRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    data = models.TextField()  # 加密数据
    data_hash = models.CharField(max_length=64)  # 区块链哈希
    created_at = models.DateTimeField(auto_now_add=True)

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    action = models.CharField(max_length=100)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
3.5 smart_community/views.py
python
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required, permission_required
from smart_community.encryption.sm4 import SM4
from smart_community.blockchain.eth_contract import store_hash
from smart_community.audit.logging import log_action
from smart_community.models import CommunityRecord
from config.settings import ENCRYPTION

@login_required
@permission_required('smart_community.add_communityrecord', raise_exception=True)
def store_data(request):
    if request.method == 'POST':
        raw_data = request.POST.get('data')
        sm4 = SM4(ENCRYPTION['SM4_KEY'])
        encrypted_data = sm4.encrypt(raw_data.encode()).hex()
        data_hash = store_hash(encrypted_data)
        record = CommunityRecord.objects.create(
            user=request.user,
            data=encrypted_data,
            data_hash=data_hash
        )
        log_action(request.user, 'store_data', f"Stored record {record.id}")
        return JsonResponse({'id': record.id, 'hash': data_hash})
    return JsonResponse({'error': 'Invalid method'}, status=400)

@login_required
@permission_required('smart_community.view_communityrecord', raise_exception=True)
def verify_data(request, id):
    try:
        record = CommunityRecord.objects.get(id=id, user=request.user)
        sm4 = SM4(ENCRYPTION['SM4_KEY'])
        decrypted_data = sm4.decrypt(bytes.fromhex(record.data)).decode()
        stored_hash = contract.functions.getHash(record.data_hash).call()
        is_valid = stored_hash == record.data_hash
        log_action(request.user, 'verify_data', f"Verified record {id}, valid: {is_valid}")
        return JsonResponse({
            'id': record.id,
            'data': decrypted_data,
            'hash': record.data_hash,
            'is_valid': is_valid
        })
    except CommunityRecord.DoesNotExist:
        return JsonResponse({'error': 'Permission denied'}, status=403)
3.6 smart_community/encryption/sm4.py
python
from gmssl import sm4

class SM4:
    def __init__(self, key):
        self.crypt = sm4.CryptSM4()
        self.key = key

    def encrypt(self, data):
        self.crypt.set_key(self.key, sm4.SM4_ENCRYPT)
        return self.crypt.crypt_ecb(data)

    def decrypt(self, data):
        self.crypt.set_key(self.key, sm4.SM4_DECRYPT)
        return self.crypt.crypt_ecb(data)
3.7 smart_community/blockchain/eth_contract.py
python
import hashlib
from web3 import Web3
import json
from config.settings import BLOCKCHAIN

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN['PROVIDER']))
with open('smart_community/blockchain/contract_abi.json', 'r') as f:
    contract_abi = json.load(f)
contract = w3.eth.contract(address=BLOCKCHAIN['CONTRACT_ADDRESS'], abi=contract_abi)

def store_hash(data: str) -> str:
    data_hash = hashlib.sha256(data.encode()).hexdigest()
    account = w3.eth.account.from_key(BLOCKCHAIN['PRIVATE_KEY'])
    tx = contract.functions.storeHash(data_hash).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 200000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_tx = w3.eth.account.sign_transaction(tx, BLOCKCHAIN['PRIVATE_KEY'])
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    return data_hash
3.8 smart_community/audit/logging.py
python
import logging
from smart_community.models import AuditLog

logger = logging.getLogger('smart_community')

def log_action(user, action, details):
    logger.info(f"User: {user.username if user else 'Anonymous'}, Action: {action}, Details: {details}")
    AuditLog.objects.create(user=user, action=action, details=details)
3.9 smart_community/permissions/rbac.py
python
from django.contrib.auth.models import Group

def assign_role(user, role):
    group, _ = Group.objects.get_or_create(name=role)
    user.groups.add(group)
3.10 contracts/DataStorage.sol
solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DataStorage {
    mapping(string => string) private hashes;

    function storeHash(string memory hash) public {
        hashes[hash] = hash;
    }

    function getHash(string memory hash) public view returns (string memory) {
        return hashes[hash];
    }
}
3.11 scripts/generate_data.py
python
import json
import os

data = [
    {"id": i, "resident_name": f"Resident_{i}", "data": f"Community record {i}"}
    for i in range(1, 11)
]
with open('data/sample_data.json', 'w') as f:
    json.dump(data, f, indent=2)
3.12 scripts/deploy_contract.py
python
from solcx import compile_source
from web3 import Web3
import json
from config.settings import BLOCKCHAIN

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN['PROVIDER']))
with open('contracts/DataStorage.sol', 'r') as f:
    source = f.read()
compiled = compile_source(source, output_values=['abi', 'bin'])
contract_id, contract_interface = compiled.popitem()
abi = contract_interface['abi']
bytecode = contract_interface['bin']

account = w3.eth.account.from_key(BLOCKCHAIN['PRIVATE_KEY'])
contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx = contract.constructor().build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 2000000,
    'gasPrice': w3.to_wei('20', 'gwei')
})
signed_tx = w3.eth.account.sign_transaction(tx, BLOCKCHAIN['PRIVATE_KEY'])
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = receipt.contractAddress
print(f"Contract deployed at {contract_address}")

with open('smart_community/blockchain/contract_abi.json', 'w') as f:
    json.dump(abi, f)
3.13 scripts/store_sample_data.py
python
import json
import requests

with open('data/sample_data.json', 'r') as f:
    data = json.load(f)

auth = ('admin', 'admin123')
for i, item in enumerate(data):
    response = requests.post(
        'http://127.0.0.1:8000/api/store/',
        auth=auth,
        json={'data': item['data']}
    )
    print(f"Record {i}: {response.json()}")
4. 配置环境
安装 Node.js 和 Ganache：
bash
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs
npm install -g ganache
启动 Ganache（后台运行）：
bash
ganache --miner.blockTime 0 &
获取私钥：
python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
private_key = w3.eth.account.from_key(w3.eth.get_transaction_count(w3.eth.accounts[0])).privateKey.hex()[2:]
print(private_key)
更新 settings.py：
编辑 config/settings.py，替换 PRIVATE_KEY：
python
BLOCKCHAIN = {
    'PROVIDER': 'http://127.0.0.1:8545',
    'CONTRACT_ADDRESS': None,
    'PRIVATE_KEY': 'your_ganache_private_key',  # 替换为实际私钥
}
5. 部署和初始化
部署智能合约：
bash
python scripts/deploy_contract.py
复制输出的合约地址，更新 settings.py：
python
BLOCKCHAIN['CONTRACT_ADDRESS'] = '0x1234567890abcdef...'
初始化数据库：
bash
python manage.py migrate
创建用户：
bash
python manage.py createsuperuser
示例：用户名 admin，密码 admin123。
创建普通用户：
bash
python manage.py shell
python
from django.contrib.auth.models import User
from smart_community.permissions.rbac import assign_role
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from smart_community.models import CommunityRecord

user = User.objects.create_user(username='resident1', password='resident123')
assign_role(user, 'resident')
content_type = ContentType.objects.get_for_model(CommunityRecord)
add_perm = Permission.objects.get(codename='add_communityrecord', content_type=content_type)
view_perm = Permission.objects.get(codename='view_communityrecord', content_type=content_type)
admin = User.objects.get(username='admin')
resident = User.objects.get(username='resident1')
admin.user_permissions.add(add_perm, view_perm)
resident.user_permissions.add(add_perm, view_perm)
assign_role(admin, 'admin')
生成样本数据：
bash
python scripts/generate_data.py
启动 Django 服务器：
bash
python manage.py runserver 0.0.0.0:8000
Codespaces 会显示端口转发链接（如 https://<your-codespace-name>.github.dev:8000）。
访问 .../admin/（用 admin 登录）或 .../api/store/。
6. 测试功能
存储数据：
bash
curl -u admin:admin123 -X POST http://127.0.0.1:8000/api/store/ -H "Content-Type: application/json" -d "{\"data\": \"社区记录 1\"}"
验证数据：
bash
curl -u admin:admin123 http://127.0.0.1:8000/api/verify/1/
存储样本数据：
bash
python scripts/store_sample_data.py
查看审计日志：
bash
cat data/audit.log
python manage.py shell
from smart_community.models import AuditLog
for log in AuditLog.objects.all():
    print(log)
7. 提交代码到 GitHub
初始化 Git（如果尚未初始化）：
bash
git init
git add .
git commit -m "Initialize smart community project"
推送到远程仓库：
bash
git remote add origin <your-repo-url>
git push -u origin main
更新 Codespaces：
Codespaces 会自动同步仓库更改。
若需重建 Codespaces，删除当前 Codespace并重新创建。
在 Codespaces 中的注意事项
端口转发：
Codespaces 自动转发 8000 端口，确保 ALLOWED_HOSTS = ['*'] 以允许访问。
如果端口未显示，检查 VS Code 的 Ports 面板，设置为 Public。
Ganache 稳定性：
Codespaces 的容器可能导致 Ganache 断开，检查：
bash
netstat -tuln | grep 8545
若失败，重新运行 ganache --miner.blockTime 0 &。
依赖安装：
如果 gmssl 或其他库失败，单独安装：
bash
pip install gmssl==3.2.1
文件权限：
确保 data/ 可写：
bash
chmod -R 777 data/
中文路径问题：
Codespaces 使用 Linux 容器，中文路径可能导致编码问题。建议将项目目录重命名为英文（如 smart-community）：
bash
mv /workspaces/面向智慧社区的数据隐私保护及所有权验证方法 /workspaces/smart-community
Transformer 模型集成
若需在 Codespaces 中集成 Transformer 数据（如 test_inversion.txt）：
上传数据：
bash
mkdir data/transformer
# 将 test_inversion.txt 上传到 data/transformer/
修改 store_sample_data.py：
python
import json
import requests
import pandas as pd

df = pd.read_csv('data/transformer/test_inversion.txt')
auth = ('admin', 'admin123')
for i, row in df.iterrows():
    data = row.to_json()
    response = requests.post(
        'http://127.0.0.1:8000/api/store/',
        auth=auth,
        json={'data': data}
    )
    print(f"Record {i}: {response.json()}")
运行：
bash
python scripts/store_sample_data.py
常见问题与排查
问题
可能原因
解决方法
私钥错误
PRIVATE_KEY 无效
从 Ganache 获取 64 字符私钥，更新 settings.py
Ganache 未运行
进程终止
运行 ganache --miner.blockTime 0 &，检查端口 8545
依赖安装失败
版本冲突
单独安装（如 pip install gmssl==3.2.1）
403 错误
权限未分配
确保用户有 add_communityrecord 和 view_communityrecord 权限
端口不可访问
Codespaces 配置错误
检查 Ports 面板，设置为 Public
验证与测试
功能验证：
存储数据，检查 CommunityRecord 表：
bash
python manage.py shell
from smart_community.models import CommunityRecord
print(CommunityRecord.objects.count())
验证记录：
bash
curl -u admin:admin123 http://127.0.0.1:8000/api/verify/1/
区块链验证：
python
from smart_community.blockchain.eth_contract import contract
from smart_community.models import CommunityRecord
record = CommunityRecord.objects.first()
stored_hash = contract.functions.getHash(record.data_hash).call()
print(stored_hash == record.data_hash)
审计日志：
bash
cat data/audit.log
结论
在 GitHub Codespaces 中，您可以基于默认 Django Hello World 项目，修改文件结构和代码，重新构建智慧社区项目。通过创建模块（加密、区块链、RBAC、审计）、配置 Ganache 和部署合约，您可以运行完整功能。Codespaces 的端口转发支持访问管理面板和 API，适合开发和测试。若需集成 Transformer 数据或进一步优化（如前端界面），请提供需求，我将提供定制代码。
祝您在 Codespaces 上成功构建项目！
引用：
GitHub Codespaces Documentation
Django Documentation