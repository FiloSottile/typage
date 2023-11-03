import url from 'url'
import path from 'path'
import express from 'express'
import puppeteer from 'puppeteer'

const __filename = url.fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

app.use(express.static(__dirname))

app.listen(0, 'localhost', async function (err) {
    if (err) throw err

    const browser = await puppeteer.launch({ headless: "new" })
    const page = await browser.newPage()
    let success = false
    page.on('console', (msg) => {
        if (msg.location && msg.location().url.includes('favicon.ico'))
            return
        if (msg.type() === 'error')
            console.error(err)
        console.log(msg.text())
        if (msg.text() === 'Hello, age!')
            success = true
    })
    page.on('pageerror', (err) => {
        console.error(err)
    })
    await page.goto('http://localhost:' + this.address().port + '/browser.html')
    await page.waitForFunction(() => globalThis.testDone)
    await browser.close()
    await this.close()
    if (!success)
        process.exit(1)
    process.exit(0)
})
