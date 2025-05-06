from django.contrib.auth.models import Group

def assign_role(user, role):
    group, _ = Group.objects.get_or_create(name=role)
    user.groups.add(group)