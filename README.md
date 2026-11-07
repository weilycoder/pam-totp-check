# pam-totp-check

以 Ubuntu 为例。

```bash
# 安装依赖
sudo apt update
sudo apt install libssl-dev libpam0g-dev

# 编译
gcc -fPIC -shared -o pam_totp_check.so pam_totp_check.c -lcrypto -lpam

# 安装 PAM 模块
sudo install -m 755 pam_totp_check.so /usr/lib/x86_64-linux-gnu/security/

# 配置 TOTP，将 JBSWY3DPEHPK3PXP 替换为你自己的密钥
sudo sh -c 'printf "%s\n" "JBSWY3DPEHPK3PXP" > /etc/security/totp.secret'
sudo chmod 600 /etc/security/totp.secret
sudo chown root:root /etc/security/totp.secret
```

然后应在合适的服务中加载 PAM 模块，例如在 `/etc/pam.d/common-auth` 中添加：

```diff
#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#
# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

+ auth sufficient pam_totp_check.so secret_file=/etc/security/totp.secret

# here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]      pam_unix.so nullok
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
auth    optional                        pam_cap.so 
# end of pam-auth-update config
```

使用 `secret=JBSWY3DPEHPK3PXP` 也可以直接在 PAM 配置中指定密钥，但不推荐这样做，因为密钥会以明文形式出现在配置文件中。
