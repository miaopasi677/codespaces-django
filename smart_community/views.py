from django.http import JsonResponse
from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render
from smart_community.encryption.sm4 import SM4
from smart_community.blockchain.eth_contract import store_hash
from smart_community.audit.logging import log_action
from smart_community.models import CommunityRecord, AuditLog
from config.settings import ENCRYPTION

def index(request):
    return render(request, 'index.html')

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

def api_docs(request):
    # 获取最近的审计日志记录
    audit_logs = AuditLog.objects.all().order_by('-timestamp')[:50]
    return render(request, 'api_docs.html', {'audit_logs': audit_logs})