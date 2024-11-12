import React, { useState } from 'react';
import styles from '../css/Cadastro.module.css';
import { RiLockPasswordLine, RiLockPasswordFill } from 'react-icons/ri';
import { FiUser } from 'react-icons/fi';

function Cadastro() {
    const [tipoUsuario, setTipoUsuario] = useState(null);
    const [nome, setNome] = useState('');
    const [usuario, setUsuario] = useState('');
    const [senha, setSenha] = useState('');
    const [senha2, setSenha2] = useState('');
    const [mensagem, setMensagem] = useState('');

    function cadastrarUsuario(e) {
        e.preventDefault();

        if (senha !== senha2) {
            setMensagem('Senhas não coincidem');
            return;
        }

        if (senha.length < 6) {
            setMensagem('Insira uma senha com pelo menos 6 caracteres');
            return;
        }

        // Preparar os dados a serem enviados
        const formData = {
            nome,
            usuario,
            senha,
            tipoUsuario
        };
        
        // Enviar dados para o Flask via requisição POST
        fetch('/cadastrarusuario', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        })
        .then(response => {
            if (response.ok) {
                // Limpar campos e exibir mensagem de sucesso
                setNome('');
                setUsuario('');
                setSenha('');
                setSenha2('');
                setTipoUsuario(null);
                setMensagem('Usuário cadastrado com sucesso!');
            } else {
                // Exibir mensagem de erro caso a requisição falhe
                setMensagem('Erro ao cadastrar usuário. Tente novamente.');
            }
        })
        .catch(error => {
            console.error('Erro ao cadastrar usuário:', error);
            setMensagem('Erro ao cadastrar usuário. Tente novamente.');
        });
    }

    const trocaUsuario = opcao => {
        if (tipoUsuario === opcao) {
            setTipoUsuario(null);
        } else {
            setTipoUsuario(opcao);
        }
    };

    return (
        <div>
            <form className={styles.form} onSubmit={cadastrarUsuario}>
                <h1>Cadastro Funcionario</h1>
                <div className={styles.inputcontainer}>
                    <div className={styles.inputgroup}>
                        <p className={styles.namegroup}><FiUser /> Nome:</p>
                        <input
                            type="text"
                            className={styles.input}
                            placeholder="Digite o nome"
                            value={nome}
                            onChange={e => setNome(e.target.value)}
                            required
                        />
                        <p className={styles.namegroup}><RiLockPasswordLine /> Senha:</p>
                        <input
                            type="password"
                            className={styles.input}
                            placeholder="Digite a senha"
                            value={senha}
                            onChange={e => setSenha(e.target.value)}
                            required
                        />
                    </div>
                    <div className={styles.inputgroup}>
                        <p className={styles.namegroup}><FiUser /> Nome de usuário:</p>
                        <input
                            type="text"
                            className={styles.input}
                            placeholder="Digite o usuário"
                            value={usuario}
                            onChange={e => setUsuario(e.target.value)}
                            required
                        />
                        <p className={styles.namegroup}><RiLockPasswordFill /> Confirme sua senha:</p>
                        <input
                            type="password"
                            className={styles.input}
                            placeholder="Confirme a senha"
                            value={senha2}
                            onChange={e => setSenha2(e.target.value)}
                            required
                        />
                    </div>
                </div>
                <div className="type">
                    <p>Tipo do funcionario:</p>
                </div>
                <label className={styles.labelgroup}>
                    <input
                        className={styles.checkboxgroup}
                        type="checkbox"
                        checked={tipoUsuario === 'gerente'}
                        onChange={() => trocaUsuario('gerente')}
                    />
                    Gerente
                </label>
                <label className={styles.labelgroup}>
                    <input
                        className={styles.checkboxgroup}
                        type="checkbox"
                        checked={tipoUsuario === 'garcom'}
                        onChange={() => trocaUsuario('garcom')}
                    />
                    Garçom
                </label>
                <label className={styles.labelgroup}>
                    <input
                        className={styles.checkboxgroup}
                        type="checkbox"
                        checked={tipoUsuario === 'caixa'}
                        onChange={() => trocaUsuario('caixa')}
                    />
                    Caixa
                </label>
                <label className={styles.labelgroup}>
                    <input
                        className={styles.checkboxgroup}
                        type="checkbox"
                        checked={tipoUsuario === 'cozinheiro'}
                        onChange={() => trocaUsuario('cozinheiro')}
                    />
                    Cozinheiro
                </label>
                <div>
                    <p>{mensagem}</p>
                </div>
                <div>
                    <input className={styles.bottomgroup} type="submit" value="Cadastrar" />
                </div>
            </form>
        </div>
    );
}

export default Cadastro;
