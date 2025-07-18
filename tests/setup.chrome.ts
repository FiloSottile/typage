const realConsoleWarn = console.warn

// https://github.com/vitest-dev/vitest/issues/6804
const annoyingWarning = '⚠️ [WEBDRIVERIO DEPRECATION NOTICE] The "switchToFrame" command is deprecated'

export default function setup() {
    console.warn = function (...args) {
        if (typeof args[0] === "string" && args[0].startsWith(annoyingWarning)) {
            return
        }
        realConsoleWarn.apply(console, args)
    }
}
