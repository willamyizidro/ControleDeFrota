import { useState, useEffect } from 'react';
import styles from '../css/Listagem.module.css';

function Listagem() {
  const [usuarios, setUsuarios] = useState([]);

  useEffect(() => {
    fetch('/listausuario')
      .then(response => response.json())
      .then(data => {
        setUsuarios(data.usuarios);
      })
      .catch(error => {
        console.error('Erro ao obter dados:', error);
      });
  }, []); 

  const excluirUsuario = (id) => {
    if (window.confirm('Tem certeza que deseja excluir?')) {
      fetch(`/excluirusuario/${id}`, {
        method: 'GET',
      })
      .then(response => {
        if (response.ok) {
          console.log('Usuário excluído com sucesso.');
          window.location.reload();
        } else {
          console.error('Falha ao excluir usuário.');
        }
      })
      .catch(error => {
        console.error('Erro ao excluir usuário:', error);
      });
    }
  };
  
  return (
    <div className={styles.Main}>
      <div className={styles.div}>
        <h1>Listagem de funcionários</h1>
        <div className={styles.tablediv}>
          <table className={styles.table}>
            <thead className={styles.colun}>
              <tr>
                <th className={styles.titlecolun}>Nome</th>
                <th className={styles.titlecolun}>Tipo</th>
                <th className={styles.titlecolun}>Ação</th>
              </tr>
            </thead>
            <tbody className={styles.tbody}>
              {usuarios.map((usuario, index) => (
                <tr key={index}>
                  <td>{usuario.nome}</td>
                  <td>{usuario.tipo}</td>
                  <td>
                    <button className={styles.buttonGroup} onClick={excluirUsuario}>
                      Editar
                    </button>{' '}
                    <button className={styles.buttonGroup} onClick={() => excluirUsuario(usuario.id)}>
                      Excluir
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default Listagem;
