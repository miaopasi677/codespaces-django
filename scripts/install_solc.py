import solcx

# 查看可用的 solc 版本
print(solcx.get_installable_solc_versions())

# 安装你需要的某个版本，比如 0.8.20
solcx.install_solc("0.8.20")

# 设置为默认使用的版本
solcx.set_solc_version("0.8.20")
