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

const lblHeartrate = document.getElementById('lbl_heartrate')

const hrsList = document.getElementById('array-hrs')
const avgLbl = document.getElementById('avg-hrs')

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

const computeAvg = async (array) => {
    // Obtain the encrypted sum
    const sumEncrypted = await main.computeAvgFuel(array);

    if (sumEncrypted != null) {
        // Decrypt data
        const quantity = 5;
        const decryptedSum = await fhe.decryptNumber(sumEncrypted);
        const avgHR = decryptedSum / quantity;
        avgLbl.innerText = "Average: " + Math.round(avgHR) + " (ppm)" 
    }
}


/* -------------------------------------------------------------------------- */
/*                              UI Rendering                                  */
/* -------------------------------------------------------------------------- */
const renderHRs = async (arrayHR) => {
    hrsList.innerHTML = '';
    let counter = 1;
    arrayHR.forEach(async (hr) => {
        const card = document.createElement('div');
        card.classList.add('card', 'card-body', 'animate__animated', 'animate__fadeIn', 'hr-card');
        card.innerHTML = `
            <div class="col d-flex align-items-center">
                <span class="title-hr"> Encrypted Heart rate [${counter}]: &nbsp;&nbsp;</span>
                <span> ${hr.substring(0,100)} ... </span>
            </div>
        `;

        // Append card to the list
        hrsList.appendChild(card);
        counter++;
    })
}


/* -------------------------------------------------------------------------- */
/*                            Initialize app                                  */
/* -------------------------------------------------------------------------- */
const init = () => {
    setInterval(async () => {
        let newHR = getRandomNumber(60, 100)
        lblHeartrate.innerText = newHR
        let encryptedHR = await main.encryptHR(newHR)
        renderHRs(encryptedHR)

        if (encryptedHR.length == 5) {
            await computeAvg(encryptedHR)
        }

    }, 4000)
}

init();