import React, { useState } from 'react';
import { useHistory } from 'react-router-dom';
import styles from '../css/Login.module.css';
import { RiLockPasswordLine } from 'react-icons/ri';
import { FiUser } from 'react-icons/fi';
import { FaBuilding } from 'react-icons/fa';

function Login() {
  const handleChange = (event) => {
    let { value } = event.target;

    value = value.replace(/\D/g, '');
    value = value.slice(0, 14);

    if (value.length <= 2) {
        value = value.replace(/^(\d{0,2})/, '$1');
      } else if (value.length <= 5) {
        value = value.replace(/^(\d{0,2})(\d{0,3})/, '$1.$2');
      } else if (value.length <= 8) {
        value = value.replace(/^(\d{0,2})(\d{0,3})(\d{0,3})/, '$1.$2.$3');
      } else if (value.length <= 12) {
        value = value.replace(/^(\d{0,2})(\d{0,3})(\d{0,3})(\d{0,4})/, '$1.$2.$3/$4');
      } else {
        value = value.replace(/^(\d{0,2})(\d{0,3})(\d{0,3})(\d{0,4})(\d{0,2})/, '$1.$2.$3/$4-$5');
        
      }

      setUsername(value);
  };
  
  const history = useHistory();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [tipoLogin, setTipoLogin] = useState('Funcionario');
  const [mensagem, setMensagem] = useState('');

  const login = async (e) => {
    e.preventDefault(); // Evita o comportamento padrão de submit do formulário

    const formData = {
      username,
      password,
    };

    try {
      const response = await fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        const data = await response.json();
        const tipoUsuario = data.tipoUsuario;

        if (tipoUsuario === 'estabelecimento') {
          history.push('/cadastro');
          window.location.reload();
        } 
      } else {
        setMensagem('Verifique seus dados.');
      }
    } catch (error) {
      console.error('Erro ao logar:', error);
      setMensagem('Ocorreu um erro ao processar o login.');
    }
  };

  const trocaUsuario = (opcao) => {
    setUsername('');
    setPassword('');
    if (tipoLogin === opcao) {
      setTipoLogin(null);
    } else {
      setTipoLogin(opcao);
    }
  };

  return (
    <div>
      <form className={styles.form} onSubmit={login}>
        <h1>Logar como:</h1>
        <label className={styles.labelgroup}>
          <input
            className={styles.checkboxgoup}
            type="checkbox"
            checked={tipoLogin === 'Funcionario'}
            onChange={(e) => trocaUsuario('Funcionario')}
          />
          Funcionário
        </label>
        <label className={styles.labelgroup}>
          <input
            className={styles.checkboxgoup}
            type="checkbox"
            checked={tipoLogin === 'Empresa'}
            onChange={(e) => trocaUsuario('Empresa')}
          />
          Empresa
        </label>

        <div className={styles.inputcontainer}>
          <div className={styles.inputgroup}>
            {tipoLogin === 'Funcionario' && (
            <>
            <p className={styles.namegroup}><FiUser /> Login:</p>
            <input
              type="text"
              className={styles.input}
              placeholder="Digite seu login"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required/>
            </>
          )}
            {tipoLogin === 'Empresa' && (
            <>
            <p className={styles.namegroup}><FaBuilding /> CNPJ:</p>
              <input type="text" 
              className={styles.input}
              placeholder="Digite seu CNPJ"
              value={username} 
              onChange={handleChange}
              required/>
              </>
            )}

            <p className={styles.namegroup}><RiLockPasswordLine /> Senha:</p>
            <input
              type="password"
              className={styles.input}
              placeholder="Digite sua senha"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
        </div>
        <div>
          <p>{mensagem}</p>
        </div>
        <div>
          <input className={styles.bottomgroup} type="submit" value="Logar" />
        </div>
      </form>
    </div>
  );
}

export default Login;
