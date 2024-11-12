from flask_login import UserMixin
import uuid
from decimal import Decimal
from peewee import *
import re



DATABASE = {
    'name': 'ControleDeFrota',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',  # ou o endereço do seu servidor PostgreSQL
    'port': 5432,          # a porta padrão do PostgreSQL é 5432
}

database = PostgresqlDatabase(
    DATABASE['name'],
    user=DATABASE['user'],
    password=DATABASE['password'],
    host=DATABASE['host'],
    port=DATABASE['port']
)


class BaseModel(Model):
    class Meta:
        database = database

class Role:
    ESTABELECIMENTO = 'estabelecimento'
    GERENTE = 'gerente'
    FUNCIONARIO = 'funcionario'


class Estabelecimento(BaseModel, UserMixin):
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    nome = CharField(max_length=100)
    cnpj = CharField(max_length=18, unique=True)
    senha = CharField(max_length=256)
    email = CharField(max_length=256)
    cidade = CharField(max_length=256)
    bairro = CharField(max_length=256)
    rua = CharField(max_length=256)
    numero = CharField(max_length=15)
    excluido = BooleanField(default=False)
    role = CharField(max_length=50, default=Role.ESTABELECIMENTO)

    def is_estabelecimento(self):
        return self.role == Role.ESTABELECIMENTO

    def __repr__(self):
        return f"Estabelecimento: {self}"


class Gerente(BaseModel, UserMixin):
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    nome = CharField(max_length=100)
    usuario = CharField(max_length=100, unique=True)
    senha = CharField(max_length=256)
    excluido = BooleanField(default=False),
    telefone = CharField(max_length=15)
    email =  CharField(max_length=100)
    estabelecimento_id = ForeignKeyField(Estabelecimento, backref='usuarios')
    role = CharField(max_length=50, default=Role.GERENTE)

    def is_gerente(self):
        return self.role == Role.GERENTE

    def __repr__(self):
        return f"Usuario: {self}"
    
    def getNome(self):
        return self.nome
    

class Funcionario(BaseModel, UserMixin):
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    nome = CharField(max_length=100)
    usuario = CharField(max_length=100, unique=True)
    senha = CharField(max_length=256)
    excluido = BooleanField(default=False),
    telefone = CharField(max_length=15)
    email =  CharField(max_length=100)
    estabelecimento_id = ForeignKeyField(Estabelecimento, backref='usuarios')
    role = CharField(max_length=50, default=Role.FUNCIONARIO)

    def is_funcionario(self):
        return self.role == Role.FUNCIONARIO

    def __repr__(self):
        return f"Usuario: {self}"
    
    def getNome(self):
        return self.nome



# Inicialize o banco de dados e crie tabelas
def create_tables():
    with database:
        database.create_tables([Estabelecimento, Gerente, Funcionario])


def obterIdEst(usuario):
    if usuario.role == "estabelecimento":
        return usuario.id
    else:
        return usuario.estabelecimento_id