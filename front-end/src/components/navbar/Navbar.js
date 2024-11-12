import { useState, useEffect } from 'react';
import styles from '../css/Navbar.module.css';
import openImage from '../imagens/fechado.png';
import closeImage from '../imagens/aberto.png';
import { useHistory } from 'react-router-dom';
import { FaHome, FaClipboardList } from "react-icons/fa";
import { MdOutlineProductionQuantityLimits, MdTableBar } from "react-icons/md";
import { IoPeople } from "react-icons/io5";
import { LuBoxes } from "react-icons/lu";
import { MdDiscount } from "react-icons/md";
import { IoIosLogOut } from "react-icons/io";


function Navbar() {

  useEffect(() => {
    fetch('/infusuario')
      .then(response => response.json())
      .then(data => {
        setUsuario(data.nome);
        setTipoUsuario(data.tipo);
      })
      .catch(error => {
        console.error('Erro ao obter dados:', error);
      });
  }, []); 

  const [usuario, setUsuario] = useState('');
  const [tipoUsuario, setTipoUsuario] = useState('');

  const handleSubitemClick = (rota) => {
    history.push(rota);
  };
  
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  const history = useHistory();

  return (
    <div className={`${styles.sidebar} ${isSidebarOpen ? styles.open : styles.closed}`}>
      <img 
        src={isSidebarOpen ? closeImage : openImage} 
        alt={isSidebarOpen ? 'Fechar Navbar' : 'Abrir Navbar'} 
        className={`${styles.togglebtn} ${styles.toggleImage}`} 
        onClick={toggleSidebar} 
      />
      <ul className={!isSidebarOpen ? styles.hideWhenClosed : ''}>
      {tipoUsuario !== '' && (
          <li>
            <button className={styles.Button} onClick={() => handleSubitemClick('/')}><FaHome /> Home</button>
          </li>
        )}

        {tipoUsuario === 'garcom' && (
          <li>
            <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-mesas')}><MdTableBar /> Abrir mesa</button>
            <button className={styles.Button} onClick={() => handleSubitemClick('/alterar-pedidos')}><MdOutlineProductionQuantityLimits /> Lançar produtos</button>
          </li>
        )}

        {tipoUsuario === 'caixa' && (
          <li>
           <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-mesas')}><MdTableBar /> Fechar mesa</button>
           <button className={styles.Button} onClick={() => handleSubitemClick('/alterar-pedidos')}><MdOutlineProductionQuantityLimits /> Lançar produtos</button>
          </li>
        )}

        {tipoUsuario === 'gerente' && (
          <>
            <li>
            <li className={styles.subitem}><MdTableBar /> Mesas</li>
            <ul className={styles.submenu}>
              <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-estoque')}><MdTableBar /> Abrir mesa</button>
              <button className={styles.Button} onClick={() => handleSubitemClick('/adicionar-produtos')}><MdTableBar /> Fechar mesa</button>
              <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-mesas')}><MdTableBar /> Visualizar mesas</button>
              <button className={styles.Button} onClick={() => handleSubitemClick('/adicionar-produtos')}><MdDiscount /> Adicionar desconto</button>
            </ul>
          </li>
          <li>
          <li className={styles.subitem}><LuBoxes /> Estoque</li>
            <ul className={styles.submenu}>
              <button className={styles.Button} onClick={() => handleSubitemClick('/addproduto')}><MdOutlineProductionQuantityLimits /> Lançar produtos</button>
              <button className={styles.Button} onClick={() => handleSubitemClick('/adicionar-produtos')}><LuBoxes /> Visualizar estoque</button>
              <button className={styles.Button} onClick={() => handleSubitemClick('/asdasd')}><LuBoxes /> Atualizar estoque</button>
            </ul>
          </li>
          </>
        )}

        {tipoUsuario === 'estabelecimento' && (
          <> 
          <li>
          <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-mesas')}><MdOutlineProductionQuantityLimits /> Lançar produtos</button>
          </li>
          <li>
          <li className={styles.subitem}><IoPeople /> Funcionarios</li>
            <ul className={styles.submenu}>
              <button className={styles.Button} onClick={() => handleSubitemClick('/cadastro')}><IoPeople /> Cadastrar funcionarios</button>
              <button className={styles.Button} onClick={() => handleSubitemClick('/listausuarios')}><IoPeople /> Visualizar funcionarios</button>
            </ul>
          </li>
          <li>
          <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-mesas')}><FaClipboardList /> Visualizar relatorios</button>
          </li>
         </>
        )}

        {tipoUsuario === 'cozinheiro' && (
          <li>
           <button className={styles.Button} onClick={() => handleSubitemClick('/visualizar-mesas')}>Visualizar pedidos</button>
          </li>
        )}

        {tipoUsuario === '' && (
          <li>
           <button className={styles.Button} onClick={() => handleSubitemClick('/login')}>Realizar login</button>
          </li>
        )}

      </ul>
      {tipoUsuario !== '' && (
        <>
          {isSidebarOpen && <p className={styles.saudacao}>Bem vindo, {usuario}</p>}
          {isSidebarOpen && <button className={styles.logoutButton} onClick={() => handleSubitemClick('/logout')}><IoIosLogOut /> Logout </button>}
        </>
      )}
    </div>
  );
}

export default Navbar;

