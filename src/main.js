/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */
const {BrowserWindow, Notification, dialog, nativeImage} = require('electron')
const fhe = require('./fhe');

/* -------------------------------------------------------------------------- */
/*                                 Constants                                  */
/* -------------------------------------------------------------------------- */
let window

let encryptedHR = new Array(5)
var counter = 0

//const logo = nativeImage.createFromPath(__dirname + './ui/res/ID_LOGO.png');

/* -------------------------------------------------------------------------- */
/*                                 Electron                                   */
/* -------------------------------------------------------------------------- */
exports.createWindow = () => {
    window = new BrowserWindow({
        show: false,
        //icon: logo,
        webPreferences: {
            contextIsolation: false,
            nodeIntegration: true
        }
    })
    window.maximize()
    window.show()
    window.loadFile('src/ui/index.html')
}

/* -------------------------------------------------------------------------- */
/*                                 FHE Logic                                  */
/* -------------------------------------------------------------------------- */
exports.generateSecretKeys = async () => {
    const saved = await fhe.generateSecretKeys();
    if (saved) {
        new Notification({
            title: 'ASIOT',
            body: '¡Las claves han sido generadas satisfactoriamente!',
            //icon: logo
        }).show()
    }
    return;
}

exports.encryptHR = async (newHR) => {
    // Encrypt data
    const newHREncrypted = await fhe.encryptNumber(newHR)
    // Save it in the array
    if (counter == 5) counter = 0
    encryptedHR[counter] = newHREncrypted
    counter++
    // Return the array
    return encryptedHR
}   

exports.computeAvgHR = async (array) => {
    return await fhe.computeAvgHR(array)
}


/* -------------------------------------------------------------------------- */
/*                                 Dialogs                                    */
/* -------------------------------------------------------------------------- */
exports.showDialog = (title, message, detail) => {
    dialog.showMessageBox({
        type: 'question',
        buttons: ['Ok'],
        //icon: logo,
        title: title,
        message: message,
        detail: detail,
    });
}