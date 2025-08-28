<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Http\Requests\User\UserChangePassword;
use App\Http\Requests\User\UserRedeemGiftCard;
use App\Http\Requests\User\UserTransfer;
use App\Http\Requests\User\UserUpdate;
use App\Models\Giftcard;
use App\Models\Order;
use App\Models\Plan;
use App\Models\Ticket;
use App\Models\User;
use App\Services\AuthService;
use App\Services\OrderService;
use App\Services\UserService;
use App\Utils\CacheKey;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    /**
     * 可信任的代理IP配置 (支持IPv4和IPv6)
     */
    private $trustedProxies = [
        // Cloudflare IPv4
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        
        // Cloudflare IPv6
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
        
        // AWS ELB/ALB 常见IP段
        '52.93.0.0/16', '54.239.0.0/16',
        
        // 阿里云SLB
        '100.64.0.0/10',
        
        // 腾讯云CLB
        '9.0.0.0/8',
        
        // 私有网络段 IPv4
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
        
        // 私有网络段 IPv6
        '::1/128',           // 本地回环
        'fc00::/7',          // 唯一本地地址
        'fe80::/10',         // 链路本地地址
        '::ffff:0:0/96',     // IPv4映射地址
    ];

    public function getActiveSession(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        $authService = new AuthService($user);
        return response([
            'data' => $authService->getSessions()
        ]);
    }

    public function removeActiveSession(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        $authService = new AuthService($user);
        return response([
            'data' => $authService->removeSession($request->input('session_id'))
        ]);
    }

    public function checkLogin(Request $request)
    {
        $data = [
            'is_login' => $request->user['id'] ? true : false
        ];
        if ($request->user['is_admin']) {
            $data['is_admin'] = true;
        }
        return response([
            'data' => $data
        ]);
    }

    public function changePassword(UserChangePassword $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        if (!Helper::multiPasswordVerify(
            $user->password_algo,
            $user->password_salt,
            $request->input('old_password'),
            $user->password
        )) {
            abort(500, __('The old password is wrong'));
        }
        $user->password = password_hash($request->input('new_password'), PASSWORD_DEFAULT);
        $user->password_algo = NULL;
        $user->password_salt = NULL;
        if (!$user->save()) {
            abort(500, __('Save failed'));
        }
        $authService = new AuthService($user);
        $authService->removeAllSession();
        return response([
            'data' => true
        ]);
    }

    public function redeemgiftcard(UserRedeemGiftCard $request)
    {
        DB::beginTransaction();

        try {
            $user = User::find($request->user['id']);
            if (!$user) {
                abort(500, __('The user does not exist'));
            }
            $giftcard_input = $request->giftcard;
            $giftcard = Giftcard::where('code', $giftcard_input)->first();

            if (!$giftcard) {
                abort(500, __('The gift card does not exist'));
            }

            $currentTime = time();
            if ($giftcard->started_at && $currentTime < $giftcard->started_at) {
                abort(500, __('The gift card is not yet valid'));
            }

            if ($giftcard->ended_at && $currentTime > $giftcard->ended_at) {
                abort(500, __('The gift card has expired'));
            }

            if ($giftcard->limit_use !== null) {
                if (!is_numeric($giftcard->limit_use) || $giftcard->limit_use <= 0) {
                    abort(500, __('The gift card usage limit has been reached'));
                }
            }

            $usedUserIds = $giftcard->used_user_ids ? json_decode($giftcard->used_user_ids, true) : [];
            if (!is_array($usedUserIds)) {
                $usedUserIds = [];
            }

            if (in_array($user->id, $usedUserIds)) {
                abort(500, __('The gift card has already been used by this user'));
            }

            $usedUserIds[] = $user->id;
            $giftcard->used_user_ids = json_encode($usedUserIds);

            switch ($giftcard->type) {
                case 1:
                    $user->balance += $giftcard->value;
                    break;
                case 2:
                    if ($user->expired_at !== null) {
                        if ($user->expired_at <= $currentTime) {
                            $user->expired_at = $currentTime + $giftcard->value * 86400;
                        } else {
                            $user->expired_at += $giftcard->value * 86400;
                        }
                    } else {
                        abort(500, __('Not suitable gift card type'));
                    }
                    break;
                case 3:
                    $user->transfer_enable += $giftcard->value * 1073741824;
                    break;
                case 4:
                    $user->u = 0;
                    $user->d = 0;
                    break;
                case 5:
                    if ($user->plan_id == null || ($user->expired_at !== null && $user->expired_at < $currentTime)) {
                        $plan = Plan::where('id', $giftcard->plan_id)->first();
                        $user->plan_id = $plan->id;
                        $user->group_id = $plan->group_id;
                        $user->transfer_enable = $plan->transfer_enable * 1073741824;
                        $user->device_limit = $plan->device_limit;
                        $user->u = 0;
                        $user->d = 0;
                        if($giftcard->value == 0) {
                            $user->expired_at = null;
                        } else {
                            $user->expired_at = $currentTime + $giftcard->value * 86400;
                        }
                    } else {
                        abort(500, __('Not suitable gift card type'));
                    }
                    break;
                default:
                    abort(500, __('Unknown gift card type'));
            }

            if ($giftcard->limit_use !== null) {
                $giftcard->limit_use -= 1;
            }

            if (!$user->save() || !$giftcard->save()) {
                throw new \Exception(__('Save failed'));
            }

            DB::commit();

            return response([
                'data' => true,
                'type' => $giftcard->type,
                'value' => $giftcard->value
            ]);
        } catch (\Exception $e) {
            DB::rollBack();
            abort(500, $e->getMessage());
        }
    }

    public function info(Request $request)
    {
        $user = User::where('id', $request->user['id'])
            ->select([
                'email',
                'transfer_enable',
                'device_limit',
                'last_login_at',
                'created_at',
                'banned',
                'auto_renewal',
                'remind_expire',
                'remind_traffic',
                'expired_at',
                'balance',
                'commission_balance',
                'plan_id',
                'discount',
                'commission_rate',
                'telegram_id',
                'uuid'
            ])
            ->first();
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        $user['avatar_url'] = 'https://cravatar.cn/avatar/' . md5($user->email) . '?s=64&d=identicon';
        return response([
            'data' => $user
        ]);
    }

    public function getStat(Request $request)
    {
        $stat = [
            Order::where('status', 0)
                ->where('user_id', $request->user['id'])
                ->count(),
            Ticket::where('status', 0)
                ->where('user_id', $request->user['id'])
                ->count(),
            User::where('invite_user_id', $request->user['id'])
                ->count()
        ];
        return response([
            'data' => $stat
        ]);
    }

    public function getSubscribe(Request $request)
    {
        $user = User::where('id', $request->user['id'])
            ->select([
                'plan_id',
                'token',
                'expired_at',
                'u',
                'd',
                'transfer_enable',
                'device_limit',
                'email',
                'uuid'
            ])
            ->first();
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        if ($user->plan_id) {
            $user['plan'] = Plan::find($user->plan_id);
            if (!$user['plan']) {
                abort(500, __('Subscription plan does not exist'));
            }
        }

        //统计在线设备
        $countalive = 0;
        $ips_array = Cache::get('ALIVE_IP_USER_' . $request->user['id']);
        if ($ips_array) {
            $countalive = $ips_array['alive_ip'];
        }
        $user['alive_ip'] = $countalive;

        $user['subscribe_url'] = Helper::getSubscribeUrl($user['token']);

        // 使用优化后的IP获取方法
        $ip = $this->getRealClientIp($request);
        
        // 获取地区信息
        $ipLocation = $this->getIpLocation($ip);
        
        // 匹配福建省及其主要城市
        if (preg_match('/福建|厦门|泉州|福州|漳州|莆田|三明|龙岩|南平|宁德/', $ipLocation)) {
            $rand = ['https://sub.mylac.cn'];
            // 如需多个备用地址，可以添加更多
            // $rand = ['https://sub.mylac.cn', 'https://sub1.mylac.cn', 'https://sub2.mylac.cn'];
            $user['subscribe_url'] = str_replace(config('v2board.subscribe_url'), $rand[array_rand($rand)], $user['subscribe_url']);
            
            // 记录地区匹配日志
            \Log::info("Regional subscription URL applied for Fujian user", [
                'user_id' => $request->user['id'],
                'ip' => $ip,
                'location' => $ipLocation,
                'new_url' => $user['subscribe_url']
            ]);
        }

        $userService = new UserService();
        $user['reset_day'] = $userService->getResetDay($user);
        return response([
            'data' => $user
        ]);
    }

    public function unbindTelegram(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        if (!$user->update(['telegram_id' => null])) {
            abort(500, __('Unbind telegram failed'));
        }
        return response([
            'data' => true
        ]);
    }

    public function resetSecurity(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        $user->uuid = Helper::guid(true);
        $user->token = Helper::guid();
        if (!$user->save()) {
            abort(500, __('Reset failed'));
        }
        return response([
            'data' => Helper::getSubscribeUrl($user['token'])
        ]);
    }

    public function update(UserUpdate $request)
    {
        $updateData = $request->only([
            'auto_renewal',
            'remind_expire',
            'remind_traffic'
        ]);

        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        try {
            $user->update($updateData);
        } catch (\Exception $e) {
            abort(500, __('Save failed'));
        }

        return response([
            'data' => true
        ]);
    }

    public function transfer(UserTransfer $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }
        if ($request->input('transfer_amount') > $user->commission_balance) {
            abort(500, __('Insufficient commission balance'));
        }
        DB::beginTransaction();
        $order = new Order();
        $orderService = new OrderService($order);
        $order->user_id = $request->user['id'];
        $order->plan_id = 0;
        $order->period = 'deposit';
        $order->trade_no = Helper::generateOrderNo();
        $order->total_amount = $request->input('transfer_amount');

        $orderService->setOrderType($user);
        $orderService->setInvite($user);

        $user->commission_balance = $user->commission_balance - $request->input('transfer_amount');
        $user->balance = $user->balance + $request->input('transfer_amount');
        $order->status = 3;
        if (!$order->save()||!$user->save()) {
            DB::rollback();
            abort(500, __('Transfer failed'));
        }

        DB::commit();

        return response([
            'data' => true
        ]);
    }

    /**
     * 获取客户端真实IP地址 (支持IPv4和IPv6)
     * 
     * @param Request $request
     * @return string
     */
    private function getRealClientIp(Request $request): string
    {
        $remoteAddr = $request->server('REMOTE_ADDR', '0.0.0.0');
        
        // 如果不是通过可信代理，直接返回REMOTE_ADDR
        if (!$this->isFromTrustedProxy($remoteAddr)) {
            return $this->validateAndCleanIp($remoteAddr);
        }

        // IP头部优先级
        $headers = [
            'CF-Connecting-IP',
            'X-Real-IP',
            'X-Forwarded-For',
            'X-Client-IP',
            'X-Cluster-Client-IP',
        ];

        // 按优先级尝试获取真实IP
        foreach ($headers as $header) {
            $ip = $this->extractIpFromHeader($request, $header);
            if ($ip && $this->isValidPublicIP($ip)) {
                return $ip;
            }
        }

        // 尝试从$_SERVER获取
        $serverKeys = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_CLIENT_IP',
        ];

        foreach ($serverKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $this->extractFirstValidIp($_SERVER[$key]);
                if ($ip && $this->isValidPublicIP($ip)) {
                    return $ip;
                }
            }
        }

        // 最后使用Laravel的默认方法
        return $this->validateAndCleanIp($request->ip());
    }

    /**
     * 从HTTP头中提取IP (支持IPv6)
     */
    private function extractIpFromHeader(Request $request, string $header): ?string
    {
        $value = $request->header($header);
        if (!$value) {
            return null;
        }

        if ($header === 'X-Forwarded-For') {
            return $this->extractFirstValidIp($value);
        }

        return $this->cleanIpString($value);
    }

    /**
     * 从逗号分隔的IP列表中提取第一个有效IP (支持IPv6)
     */
    private function extractFirstValidIp(string $value): ?string
    {
        $ips = array_map('trim', explode(',', $value));
        
        // 优先返回公网IP
        foreach ($ips as $ip) {
            $cleanIp = $this->cleanIpString($ip);
            if ($cleanIp && $this->isValidPublicIP($cleanIp)) {
                return $cleanIp;
            }
        }
        
        // 如果没有公网IP，返回第一个有效IP
        foreach ($ips as $ip) {
            $cleanIp = $this->cleanIpString($ip);
            if ($cleanIp && $this->isValidIp($cleanIp)) {
                return $cleanIp;
            }
        }
        
        return null;
    }

    /**
     * 清理IP字符串 (支持IPv6)
     */
    private function cleanIpString(string $ip): string
    {
        $ip = trim($ip, ' "\'');
        
        // 处理IPv6地址的方括号
        if (strpos($ip, '[') === 0 && strpos($ip, ']') !== false) {
            // IPv6格式: [2001:db8::1]:8080 或 [2001:db8::1]
            preg_match('/\[([^\]]+)\]/', $ip, $matches);
            if (isset($matches[1])) {
                $ip = $matches[1];
            }
        } elseif (strpos($ip, ':') !== false) {
            // 检查是否为IPv4:port格式
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                // 这是一个IPv6地址，保持原样
            } else {
                // 这可能是IPv4:port，移除端口
                $parts = explode(':', $ip);
                if (count($parts) == 2 && is_numeric($parts[1])) {
                    $ip = $parts[0];
                }
            }
        }
        
        return trim($ip);
    }

    /**
     * 验证并清理IP地址 (支持IPv6)
     */
    private function validateAndCleanIp(string $ip): string
    {
        $cleaned = $this->cleanIpString($ip);
        return $this->isValidIp($cleaned) ? $cleaned : '0.0.0.0';
    }

    /**
     * 检查IP是否有效 (支持IPv4和IPv6)
     */
    private function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * 检查是否为有效的公网IP (支持IPv4和IPv6)
     */
    private function isValidPublicIP(string $ip): bool
    {
        // 基本IP格式验证
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // 检查是否为公网IP (同时支持IPv4和IPv6)
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    /**
     * 检查是否来自可信代理 (支持IPv4和IPv6)
     */
    private function isFromTrustedProxy(string $remoteAddr): bool
    {
        foreach ($this->trustedProxies as $proxy) {
            if ($this->ipInRange($remoteAddr, $proxy)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查IP是否在指定范围内 (支持IPv4和IPv6)
     */
    private function ipInRange(string $ip, string $cidr): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        
        [$subnet, $mask] = explode('/', $cidr);
        
        // IPv6处理
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->ipv6InRange($ip, $subnet, (int)$mask);
        }
        
        // IPv4处理 (原有逻辑)
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || 
            !filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        
        $maskLong = -1 << (32 - (int)$mask);
        
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }

    /**
     * IPv6范围检查
     * 
     * @param string $ip
     * @param string $subnet
     * @param int $prefixLength
     * @return bool
     */
    private function ipv6InRange(string $ip, string $subnet, int $prefixLength): bool
    {
        $ip = inet_pton($ip);
        $subnet = inet_pton($subnet);
        
        if (!$ip || !$subnet) {
            return false;
        }
        
        // 计算需要比较的字节数和位数
        $bytesToCheck = intval($prefixLength / 8);
        $bitsToCheck = $prefixLength % 8;
        
        // 比较完整字节
        for ($i = 0; $i < $bytesToCheck; $i++) {
            if ($ip[$i] !== $subnet[$i]) {
                return false;
            }
        }
        
        // 比较剩余位
        if ($bitsToCheck > 0 && $bytesToCheck < 16) {
            $mask = 0xFF << (8 - $bitsToCheck);
            return (ord($ip[$bytesToCheck]) & $mask) === (ord($subnet[$bytesToCheck]) & $mask);
        }
        
        return true;
    }

    /**
     * 检查是否为IPv6地址
     * 
     * @param string $ip
     * @return bool
     */
    private function isIPv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * ===========================================
     *           IP地理位置查询API配置区域
     * ===========================================
     * 可以在这里集中管理所有IP查询相关的API
     */

    /**
     * IP地理位置查询API配置 (支持IPv6)
     * 可以根据需要调整API的优先级和参数
     */
    private function getIpLocationApiConfig(): array
    {
        return [
            // 主API: ip-api.com (推荐 - 免费、准确、支持中文、支持IPv6)
            'primary' => [
                'name' => 'ip-api.com',
                'url_template' => 'http://ip-api.com/json/{ip}?fields=status,country,regionName&lang=zh-CN',
                'timeout' => 3,
                'method' => 'tryIpApiCom',
                'supports_ipv6' => true
            ],
            
            // 备用API: ipapi.co (稳定的备选方案、支持IPv6)
            'backup' => [
                'name' => 'ipapi.co', 
                'url_template' => 'https://ipapi.co/{ip}/region_name/',
                'timeout' => 4,
                'method' => 'tryIpApiCo',
                'supports_ipv6' => true
            ],
            
            // 可选的第三备用API（如需启用，取消注释）
            /*
            'backup2' => [
                'name' => 'ipinfo.io',
                'url_template' => 'https://ipinfo.io/{ip}/json',
                'timeout' => 3,
                'method' => 'tryIpInfoIo',
                'supports_ipv6' => true
            ],
            
            'backup3' => [
                'name' => 'ip2location', // 专业的IPv6支持
                'url_template' => 'https://api.ip2location.com/v2/?ip={ip}&key=demo&package=WS24',
                'timeout' => 4,
                'method' => 'tryIp2LocationApi',
                'supports_ipv6' => true
            ],
            
            'backup4' => [
                'name' => 'taobao', // 国内用户友好 (仅IPv4)
                'url_template' => 'https://ip.taobao.com/outGetIpInfo?ip={ip}&accessKey=alibaba-inc',
                'timeout' => 4,
                'method' => 'tryTaobaoApi',
                'supports_ipv6' => false
            ]
            */
        ];
    }

    /**
     * 获取IP地理位置信息 (支持IPv4和IPv6)
     * 使用配置化的API列表
     * 
     * @param string $ip
     * @return string
     */
    private function getIpLocation(string $ip): string
    {
        // 检查缓存
        $cacheKey = "ip_location:" . hash('md5', $ip); // 使用hash避免IPv6冒号问题
        $cached = Cache::get($cacheKey);
        if ($cached) {
            return $cached;
        }

        // 检查是否为私有IP
        if (!$this->isValidPublicIP($ip)) {
            $result = $this->isIPv6($ip) ? "内网IPv6" : "内网IPv4";
            Cache::put($cacheKey, $result, 3600);
            return $result;
        }

        // 获取API配置
        $apiConfig = $this->getIpLocationApiConfig();

        // 检查IP类型并选择合适的API
        $isIPv6 = $this->isIPv6($ip);

        // 尝试主API
        if (isset($apiConfig['primary']) && 
            (!$isIPv6 || ($apiConfig['primary']['supports_ipv6'] ?? false))) {
            $location = $this->{$apiConfig['primary']['method']}($ip);
            if ($location) {
                Cache::put($cacheKey, $location, 3600);
                return $location;
            }
        }

        // 尝试备用API
        if (isset($apiConfig['backup']) && 
            (!$isIPv6 || ($apiConfig['backup']['supports_ipv6'] ?? false))) {
            $location = $this->{$apiConfig['backup']['method']}($ip);
            if ($location) {
                Cache::put($cacheKey, $location, 3600);
                return $location;
            }
        }

        // 如果有更多备用API，可以继续尝试
        foreach (['backup2', 'backup3', 'backup4'] as $backupKey) {
            if (isset($apiConfig[$backupKey]) && 
                (!$isIPv6 || ($apiConfig[$backupKey]['supports_ipv6'] ?? false))) {
                $location = $this->{$apiConfig[$backupKey]['method']}($ip);
                if ($location) {
                    Cache::put($cacheKey, $location, 3600);
                    return $location;
                }
            }
        }

        $fallback = $isIPv6 ? "未知地区(IPv6)" : "未知地区";
        Cache::put($cacheKey, $fallback, 600);
        return $fallback;
    }

    /**
     * ===========================================
     *              API实现方法区域
     * ===========================================
     * 所有具体的API调用实现都在这里
     */

    /**
     * 尝试使用ip-api.com获取IP位置
     * API文档: http://ip-api.com/docs/
     * 限制: 免费版每分钟45次请求
     * IPv6支持: 完全支持
     * 
     * @param string $ip
     * @return string|null
     */
    private function tryIpApiCom(string $ip): ?string
    {
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=status,country,regionName&lang=zh-CN";
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 3,
                    'method' => 'GET',
                    'header' => 'User-Agent: Mozilla/5.0 (compatible; V2Board/1.0)'
                ]
            ]);

            $response = @file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && $data['status'] === 'success') {
                    $location = trim($data['regionName'] ?? $data['country'] ?? '');
                    if (!empty($location)) {
                        return $location;
                    }
                }
            }
        } catch (\Exception $e) {
            // 静默处理错误
        }
        
        return null;
    }

    /**
     * 尝试使用ipapi.co获取IP位置
     * API文档: https://ipapi.co/api/
     * 限制: 免费版每月1000次请求
     * IPv6支持: 完全支持
     * 
     * @param string $ip
     * @return string|null
     */
    private function tryIpApiCo(string $ip): ?string
    {
        try {
            $url = "https://ipapi.co/{$ip}/region_name/";
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 4,
                    'method' => 'GET',
                    'header' => 'User-Agent: Mozilla/5.0 (compatible; V2Board/1.0)'
                ]
            ]);

            $response = @file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $location = trim($response);
                if (!empty($location) && $location !== 'Unknown') {
                    return $location;
                }
            }
        } catch (\Exception $e) {
            // 静默处理错误
        }
        
        return null;
    }

    /**
     * 尝试使用ipinfo.io获取IP位置
     * API文档: https://ipinfo.io/developers
     * 限制: 免费版每月1000次请求
     * IPv6支持: 完全支持
     * 如需启用，请在getIpLocationApiConfig()中取消注释
     * 
     * @param string $ip
     * @return string|null
     */
    private function tryIpInfoIo(string $ip): ?string
    {
        try {
            $url = "https://ipinfo.io/{$ip}/json";
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 3,
                    'method' => 'GET',
                    'header' => 'User-Agent: Mozilla/5.0 (compatible; V2Board/1.0)'
                ]
            ]);

            $response = @file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['region'])) {
                    $location = trim($data['region'] ?? $data['country'] ?? '');
                    if (!empty($location)) {
                        return $location;
                    }
                }
            }
        } catch (\Exception $e) {
            // 静默处理错误
        }
        
        return null;
    }

    /**
     * 尝试使用IP2Location获取IP位置
     * API文档: https://www.ip2location.com/web-service/ip2location
     * 限制: 需要API密钥，demo密钥有限制
     * IPv6支持: 完全支持
     * 如需启用，请在getIpLocationApiConfig()中取消注释并配置API密钥
     * 
     * @param string $ip
     * @return string|null
     */
    private function tryIp2LocationApi(string $ip): ?string
    {
        try {
            // 注意：这里使用的是demo密钥，生产环境需要购买API密钥
            $url = "https://api.ip2location.com/v2/?ip={$ip}&key=demo&package=WS24";
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 4,
                    'method' => 'GET',
                    'header' => 'User-Agent: Mozilla/5.0 (compatible; V2Board/1.0)'
                ]
            ]);

            $response = @file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['region_name'])) {
                    $location = trim($data['region_name'] ?? $data['country_name'] ?? '');
                    if (!empty($location)) {
                        return $location;
                    }
                }
            }
        } catch (\Exception $e) {
            // 静默处理错误
        }
        
        return null;
    }

    /**
     * 尝试使用淘宝IP库获取位置
     * 适合国内用户，对中国IP识别准确度高
     * IPv6支持: 不支持，仅支持IPv4
     * 如需启用，请在getIpLocationApiConfig()中取消注释
     * 
     * @param string $ip
     * @return string|null
     */
    private function tryTaobaoApi(string $ip): ?string
    {
        try {
            // 淘宝API不支持IPv6，直接跳过
            if ($this->isIPv6($ip)) {
                return null;
            }
            
            $url = "https://ip.taobao.com/outGetIpInfo?ip={$ip}&accessKey=alibaba-inc";
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 4,
                    'method' => 'GET',
                    'header' => 'User-Agent: Mozilla/5.0 (compatible; V2Board/1.0)'
                ]
            ]);

            $response = @file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && $data['code'] == 0 && isset($data['data'])) {
                    $locationData = $data['data'];
                    $location = trim($locationData['region'] ?? $locationData['country'] ?? '');
                    if (!empty($location)) {
                        return $location;
                    }
                }
            }
        } catch (\Exception $e) {
            // 静默处理错误
        }
        
        return null;
    }

    public function getQuickLoginUrl(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, __('The user does not exist'));
        }

        $code = Helper::guid();
        $key = CacheKey::get('TEMP_TOKEN', $code);
        Cache::put($key, $user->id, 60);
        $redirect = '/#/login?verify=' . $code . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
        if (config('v2board.app_url')) {
            $url = config('v2board.app_url') . $redirect;
        } else {
            $url = url($redirect);
        }
        return response([
            'data' => $url
        ]);
    }
}