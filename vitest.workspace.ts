import { readdir, readFile } from "fs/promises"
import { defineWorkspace } from "vitest/config"
import type { BrowserCommand } from "vitest/node"
import { base64 } from "@scure/base"

const listTestkitFiles: BrowserCommand<[]> = ({ testPath }) => {
    testPath = testPath?.split("/").slice(0, -1).join("/")
    return readdir((testPath ?? ".") + "/testkit")
}

const readTestkitFile: BrowserCommand<[name: string]> = async ({ testPath }, name) => {
    testPath = testPath?.split("/").slice(0, -1).join("/")
    return base64.encode(await readFile((testPath ?? ".") + "/testkit/" + name))
}

export default defineWorkspace([
    {
        test: {
            name: "node",
            environment: "node",
        },
    },
    {
        test: {
            name: "firefox",
            browser: {
                enabled: true,
                headless: true,
                name: "firefox",
                provider: "webdriverio",
                commands: {
                    listTestkitFiles,
                    readTestkitFile,
                },
            },
        },
    },
    {
        test: {
            name: "chrome",
            browser: {
                enabled: true,
                headless: true,
                name: "chrome",
                provider: "webdriverio",
                commands: {
                    listTestkitFiles,
                    readTestkitFile,
                },
            },
            globalSetup: "tests/setup.chrome.ts",
        },
    },
])
