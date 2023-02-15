/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */
const {remote} = require('electron');
const main = remote.require('./main');
const fhe = remote.require('./fhe');

/* -------------------------------------------------------------------------- */
/*                                 Constants                                  */
/* -------------------------------------------------------------------------- */
const genKeys = document.getElementById('generate-keys')
const lblGenerationInfo = document.getElementById('generation-info')

const getRandomNumber = (min, max) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/* -------------------------------------------------------------------------- */
/*                           Event Listeners                                  */
/* -------------------------------------------------------------------------- */
genKeys.addEventListener('click', async () => {
    lblGenerationInfo.innerText = 'Generando claves ...';
    await main.generateSecretKeys();
    lblGenerationInfo.innerText = '';
})

/* -------------------------------------------------------------------------- */
/*                              UI Rendering                                  */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/*                            Initialize app                                  */
/* -------------------------------------------------------------------------- */
const init = () => {
    
}

init();