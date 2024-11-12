# utils.py

from functools import wraps
from flask import abort
from flask_login import current_user
from models import Role

def estabelecimento_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != Role.ESTABELECIMENTO:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return decorated_function

def estabelecimento_or_gerente_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != Role.ESTABELECIMENTO or current_user.role != Role.GERENTE:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return decorated_function

def funcionario_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in [Role.ESTABELECIMENTO, Role.FUNCIONARIO, Role.GERENTE]:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return decorated_function

def gerente_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in [Role.ESTABELECIMENTO, Role.GERENTE]:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return decorated_function

