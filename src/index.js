const {createWindow} = require('./main')
const {app} = require('electron')
require('electron-reload')(__dirname)

process.setMaxListeners(Infinity);

app.allowRendererProcessReuse = false
app.whenReady().then(createWindow)