# سه مسیر بک‌هال (وقتی WaterWall یا هلند مستقیم قطع شد)

| # | مسیر | چه زمانی |
|---|------|----------|
| ۱ | WaterWall / REALITY / CDN (`TO-AMS-*`) | حالت عادی |
| ۲ | ورود مستقیم به نود هلند (MobinHost) | وقتی WW خراب است ولی IP هلند باز است |
| ۳ | **VPN روی SSH** | وقتی WW و مستقیم هلند هر دو مسدودند |

## مسیر سوم (SSH)

روی شتابان دو دسته تونل SOCKS موازی است:

- **`TO-AMS-SSH`** → نت‌کاپ / Exit آلمان (`:18300`) — از قبل در پروداکشن
- **`TO-NL-SSH`** → MobinHost هلند (`:18400`) — مسیر سوم

نصب: `vpn-infra-kit/iran/ssh-path/setup-ssh-path-nl.sh` + `scripts/add_nl_ssh_outbound.py`  
جزئیات: [SSH-PATH.md در vpn-infra-kit](https://github.com/rootitdev/vpn-infra-kit/blob/main/docs/SSH-PATH.md)

در پنل `/path/` می‌توانید مسیر را روی **SSH → هلند** (`ssh-nl`) قفل کنید.
