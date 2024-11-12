from flask import Flask, render_template, redirect, url_for , request, jsonify, session
from models import *
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from utils import *
from flask_cors import CORS


app = Flask("__main__")


def initialize_app():
    app.config['SECRET_KEY'] = 'CHAVESECRETA'
    database.connect()
    CORS(app)
    create_tables()  # Cria tabelas se não existirem
    print("Conexão com o banco de dados estabelecida.")

@app.route('/')
def index():
    return render_template('index.html')

# Rota para servir os arquivos estáticos
@app.route('/static/<path:path>')
def static_proxy(path):
    return app.send_static_file(path)

# Rota para lidar com todas as outras rotas do lado do cliente
@app.route('/<path:path>')
def catch_all(path):
    return render_template('index.html')


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        try:
            usuario = Funcionario.get(Funcionario.id == user_id)
            return usuario
        except Funcionario.DoesNotExist:
            try:
                usuario = Gerente.get(Gerente.id == user_id)
                return usuario
            except Gerente.DoesNotExist:
                try:
                    estabelecimento = Estabelecimento.get(Estabelecimento.id == user_id)
                    return estabelecimento
                except Estabelecimento.DoesNotExist:
                    return None 
            

@app.errorhandler(403)
def forbidden(error):
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    estabelecimento = Estabelecimento.get_or_none(cnpj=username)
    if estabelecimento:
        if check_password_hash(estabelecimento.senha, password):
            session['user_id'] = estabelecimento.id
            login_user(estabelecimento)
            return jsonify({'tipoUsuario': 'estabelecimento'}), 200
        else:
            return jsonify({'error': 'Senha incorreta'}), 401

    gerente = Gerente.get_or_none(usuario=username)
    if gerente:
        if check_password_hash(gerente.senha, password):
            session['user_id'] = gerente.id
            login_user(gerente)
            return jsonify({'tipoUsuario': 'gerente'}), 200
        else:
            return jsonify({'error': 'Senha incorreta'}), 401

    funcionario = Funcionario.get_or_none(usuario=username)
    if funcionario:
        if check_password_hash(funcionario.senha, password):
            session['user_id'] = funcionario.id
            login_user(funcionario)
            return jsonify({'tipoUsuario': 'funcionario'}), 200
        else:
            return jsonify({'error': 'Senha incorreta'}), 401

    return jsonify({'error': 'Usuário não encontrado'}), 404


# cadastro empresa
@app.route('/estabelecimento', methods=['POST'])
def cadastrar_estabelecimento():
    data = request.get_json()

    nome = data['nome']
    cnpj = data['cnpj']
    senha = generate_password_hash((data['senha']))
    cidade = data['cidade']
    bairro= data['bairro']
    rua = data['rua']
    numero  = data['numero']
    email = data['email']
 
    try:
        Estabelecimento.create(nome = nome, cnpj = cnpj, senha = senha, cidade = cidade, bairro = bairro, rua = rua, numero = numero, email = email)
        return jsonify({'message': 'Estabelecimento cadastrado com sucesso'}), 200
  
    except IntegrityError as e:
        return jsonify({'message': 'Erro de integridade: já existe um estabelecimento com este CNPJ.'}), 400

    except DataError as e:
        return jsonify({'message': 'Erro nos dados: verifique se os dados estão corretos.'}), 400

    except (OperationalError, ProgrammingError) as e:
        return jsonify({'message': f'Erro no banco de dados: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'message': f'Erro inesperado: {str(e)}'}), 500

# cadastro gerente
@app.route('/gerente', methods=['POST'])
@login_required
@estabelecimento_required
def cadastrar_gerente():
    data = request.get_json()
    nome = data['nome']
    usuario = data['usuario']
    senha = generate_password_hash((data['senha']))
    email = data['email']
    telefone = data['telefone']
    estabelecimento_id = current_user.id
    try:
        Gerente.create(nome = nome, usuario = usuario, senha = senha , estabelecimento_id =  estabelecimento_id, email = email, telefone = telefone)
        return jsonify({'message': 'Usuario cadastrado com sucesso'}), 200
    
    except IntegrityError as e:
        return jsonify({'message': 'Erro de integridade: já existe um tecnico com este usuario.'}), 400

    except DataError as e:
        return jsonify({'message': 'Erro nos dados: verifique se os dados estão corretos.'}), 400

    except (OperationalError, ProgrammingError) as e:
        return jsonify({'message': f'Erro no banco de dados: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'message': f'Erro inesperado: {str(e)}'}), 500
    
# cadastro de funcionario
@app.route('/funcionario', methods=['POST'])
@login_required
@estabelecimento_required
def cadastrar_funcionario():
    data = request.get_json()
    nome = data['nome']
    usuario = data['usuario']
    senha = generate_password_hash((data['senha']))
    email = data['email']
    telefone = data['telefone']
    estabelecimento_id = current_user.id
    try:
        Funcionario.create(nome = nome, usuario = usuario, senha = senha , estabelecimento_id =  estabelecimento_id, email = email, telefone = telefone)
        return jsonify({'message': 'Usuario cadastrado com sucesso'}), 200
    
    except IntegrityError as e:
        return jsonify({'message': 'Erro de integridade: já existe um tecnico com este usuario.'}), 400

    except DataError as e:
        return jsonify({'message': 'Erro nos dados: verifique se os dados estão corretos.'}), 400

    except (OperationalError, ProgrammingError) as e:
        return jsonify({'message': f'Erro no banco de dados: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'message': f'Erro inesperado: {str(e)}'}), 500


@app.route('/cadastro', methods=['GET'])
@login_required
@estabelecimento_required
def cadastro():
    return render_template('index.html')



@app.route('/listausuarios', methods=['GET'])
@login_required
@estabelecimento_required
def listagem():
    return render_template('index.html')


@app.route('/infusuario', methods=['GET'])
@login_required
def infusuario():
    usuario = load_user(current_user.id)
    nome = usuario.nome
    tipo = usuario.role
    return jsonify({'nome': nome,'tipo':tipo}), 200




if __name__ == '__main__':
    initialize_app()
    app.run(debug=True)