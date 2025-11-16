rule SuspiciousExec
{
    strings:
        $exec = "exec("
        $eval = "eval("
        $subprocess = "subprocess."
        $popen = "popen("
        $system = "os.system("
        $shell = "shell=True"
    condition:
        any of them
}

rule FileSystemAccess
{
    strings:
        $read1 = "fs.readFile"
        $write1 = "fs.writeFile"
        $open1 = "open("
        $chmod1 = "chmod("
        $unlink1 = "unlink("
        $remove1 = "os.remove"
        $rmdir1 = "os.rmdir"
        $mkdir1 = "os.mkdir"
    condition:
        any of them
}

rule CryptoOperations
{
    strings:
        $crypto1 = "crypto.randomBytes"
        $crypto2 = "crypto.createHash"
        $base641 = "base64.b64encode"
        $base642 = "base64.b64decode"
        $base643 = "btoa("
        $base644 = "atob("
        $encrypt1 = "encrypt("
        $decrypt1 = "decrypt("
    condition:
        any of them
}

rule EnvironmentAccess
{
    strings:
        $env1 = "process.env"
        $env2 = "os.environ"
        $env3 = "getenv("
        $env4 = "setenv("
        $path1 = "process.cwd"
        $path2 = "os.getcwd"
        $path3 = "__dirname"
        $path4 = "__file__"
    condition:
        any of them
}

rule SuspiciousPatterns
{
    strings:
        $obfuscated1 = /[a-zA-Z_][a-zA-Z0-9_]*\[['"]\w+['"]\]/
        $hex1 = /\\x[0-9a-fA-F]{2}/
        $unicode1 = /\\u[0-9a-fA-F]{4}/
        $eval_pattern = /(eval|exec)\s*\(/
        $require_resolve = /require\.resolve/
    condition:
        any of them
}

rule PostInstallScripts
{
    strings:
        $postinstall = "postinstall"
        $preinstall = "preinstall"
        $install_script = "install:"
        $npm_script = "npm run"
        $node_script = "node "
    condition:
        any of them
}

rule DangerousFunctions
{
    strings:
        $function_constructor = "Function("
        $settimeout = "setTimeout("
        $setinterval = "setInterval("
        $require_dynamic = /require\s*\(\s*[a-zA-Z_]/
        $import_dynamic = /import\s*\(\s*[a-zA-Z_]/
        $vm_run = "vm.runInThisContext"
        $vm_script = "vm.Script"
    condition:
        any of them
}
