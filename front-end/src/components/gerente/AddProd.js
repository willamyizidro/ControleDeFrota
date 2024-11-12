import React, { useState } from 'react';
import styles from '../css/AddProd.module.css';
import { FaMoneyCheckDollar } from "react-icons/fa6";
import { AiFillProduct } from "react-icons/ai";
import { SlOptionsVertical } from "react-icons/sl";

function AddProd() {

  const [mensagem, setMensagem] = useState('');
  const [categoria, setTipoProd] = useState('');
  const [nome, setNomeProd] = useState('');
  const [valor, setPreco] = useState('');

  const trocaTipoProd = (event) => {
    setTipoProd(event.target.value);
  };

  const mudaPreco = (event) => {
    const inputPrice = event.target.value;

    
    const numericPrice = inputPrice.replace(/[^0-9.]/g, '');

    setPreco(numericPrice);
  };

  function adicionarProduto(e){
    e.preventDefault();

    if (categoria === 'err'){
      setMensagem('Selecione um tipo de prato valido.')
    }

    const formData = {
      nome,
      categoria,
      valor,
    };
  
  fetch('/produto', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
  })
  .then(response => {
      if (response.ok) {
          setTipoProd('');
          setNomeProd('');
          setPreco('');
          setMensagem('Produto cadastrado com sucesso!');
          console.log(formData)
      } else {
          // Exibir mensagem de erro caso a requisição falhe
          setMensagem('Erro ao cadastrar produto. Tente novamente.');
      }
  })
  .catch(error => {
      console.error('Erro ao cadastrar do produto:', error);
      setMensagem('Erro ao cadastrar produto. Tente novamente.');
  });
  }

  return (
    <div>
    <form className={styles.form} onSubmit={adicionarProduto}>
                <h1>Adicionar produtos</h1>
                <div className={styles.inputcontainer}>
                    <div className={styles.inputgroup}>

                    <p className={styles.namegroup}><SlOptionsVertical /> Tipo de prato:</p>
                    <select className ={styles.inputlist} value={categoria} onChange={trocaTipoProd}>
                      <option value="err">Selecione o tipo</option>
                      <option value="entrada">Entrada</option>
                      <option value="prato_principal">Prato principal</option>
                      <option value="sobremesa">Sobremesa</option>
                      <option value="bebida">Bebida</option>
                      <option value="drink">Dink</option>
                      <option value="petisco">Petisco</option>
                    </select>
                  
                    <p className={styles.namegroup}><AiFillProduct /> Nome:</p>
                        <input
                            type="text"
                            className={styles.input}
                            placeholder="Digite o nome"
                            value={nome}
                            onChange={e => setNomeProd(e.target.value)}
                            required
                        />

                    <p className={styles.namegroup}><FaMoneyCheckDollar /> Preco:</p>
                        <input
                            type="text"
                            className={styles.input}
                            placeholder="Digite o preco"
                            value={valor}
                            onChange={mudaPreco}
                            required
                        />
                    </div>
                </div>
                <div>
                    <p>{mensagem}</p>
                </div>
                <div>
                    <input className={styles.bottomgroup} type="submit" value="Enviar" />
                </div>
            </form>
  </div>
  );
}

export default AddProd;
