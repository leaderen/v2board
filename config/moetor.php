<?php
// ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐ \\
// │ Moetor                                                                                                | \\
// |                                                                                                       | \\
// │ 注意:保存后在项目根目录执行：php artisan config:cache 才会生效                                           | \\
// ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤ \\
// │ 客户端打包 @parkerstb                                                                                  │ \\
// └───────────────────────────────────────────────────────────────────────────────────────────────────────┘ \\
return [
    
    # 无需填写
    'license' => '',
    
    # Crisp在线客服，不填写则入口隐藏
    'crispId' => '0129db6f-fa04-49f0-a697-1a3b45b54909',
    
    # 邀请链接，APP里点复制链接，邀请码会拼接在最后
    'inviteUrl' => 'https://cljs.me?love=',
    
    # 订阅链接来源：1=从面板获取，2=从当前app检测后的api做拼接，3=将打包地址中的多个api拼接后做检测
    'subUrlSource' => 1,
    
    # 是否显示流量明细入口 true=显示，false=隐藏
    'trafficLogShow' => true,
    
    # 版本更新时是否强制，最新版本信息请在面板-系统配置-APP-Android进行配置，下载地址需要apk文件直链url
    'versionUpdateForce' => true,
    
    # 版本更新是否跳转：true=跳转到下载地址（在面板里配置），false=app应用内更新直接下载安装（面板里的下载地址需要直链）
    'versionUpdateJump' => false,
    
    # 节点延迟的展示相关
    'nodeDelayShow' => [
        'type' => 1,            # 展示方式：0=延迟数值，1=信号图标
        'discount' => 60,       # 延迟打折：降低展示的延迟值，打9折就填90，即延迟100显示90，填0或大于100无效
        'colorBest' => 900,    # 延迟数值/图标颜色：延迟小于此值为绿色
        'colorGood' => 1500,    # 延迟数值/图标颜色：延迟小于此值并大于{colorBest}为黄色，大于此值为红色
    ],
    
    # 无限流量的展示条件及文本
    'trafficUnlimited' => [
        'value' => 99999,             # 套餐流量为此值时展示（GB），填0或不填时不启用
        'text' => '无限制',       # 在app中的展示文本
    ],
    
    # 商店相关
    'shop' => [
        # 商店列表不展示的套餐ID，不填写则全部展示
        'shopExcludeIds' => [],
        
        # 套餐自定义描述,app将优先展示此处的描述，若此处为空，则获取面板里配置的
        'description' => [
            # 样例，无特殊需求无需配置
            //[
            //    'id' => 3,      # 套餐ID
            //    'content' => '[
            #        {'feature': '每月 100GB 流量','support': true},
            #        {'feature': '每月购买日自动重置流量','support': true}, 
            #        {'feature': '多地BGP跨境专线出国','support': true},
            #        {'feature': '解锁ChatGPT/Netflix/TikTok等','support': true},
            #        {'feature': '全球 10+ 国家/地区 20+ 节点','support': true},
            #        {'feature': 'SS-Obfs协议，支持 3 台设备同时使用','support': true}
            #    ]'
            //],
            //[
            //    'id' => 4,
            //    'content' => '[
            #        {'feature': '每月 200GB 流量','support': true},
            #        {'feature': '每月购买日自动重置流量','support': true}, 
            #        {'feature': '多地BGP跨境专线出国','support': true},
            #        {'feature': '解锁ChatGPT/Netflix/TikTok等','support': true},
            #        {'feature': '全球 10+ 国家/地区 20+ 节点','support': true},
            #        {'feature': 'SS-Obfs协议，支持 5 台设备同时使用','support': true}
            #    ]'
            //],
        ],  
    ],
    
    # 用户协议及隐私政策
    'agreements' => [
        'show' => true,         # 是否显示（总开关：[第一次进入app、登录、注册、其他设置-关于]的显示）
        'title' => '个人信息保护提示',      # 第一次进入 app 的弹窗标题
        # 第一次进入 app 的弹窗内容，支持文字a标签跳转
        'content' => '感谢您使用草榴加速！我们将依据<a href="https://google.com">《服务协议》</a>来帮助您了解我们在收集、使用、存储和共享您个人信息的情况以及您享有的相关权利。<br><br>1、您可以通过查看《服务协议》来了解我们可能收集、使用的您的个人信息情况；<br><br>2、基于您的明示授权，我们可能调用您的重要设备权限。我们将在首次调用时逐项询问您是否允许使用该权限，您有权拒绝或取消授权；<br><br>3、我们会采取业界先进的安全措施保护您的信息安全；<br><br>4、您可以查询、更正、删除、撤回授权您的个人信息，我们也提供账户注销的渠道。<br><br>',
         # 服务协议url
        'serviceLink' => 'https://google.com',
        # 隐私政策url
        'privacyLink' => 'https://google.com',
    ],
    
    # 每次进入app时的弹窗，支持多弹窗队列弹出
    'noticeList' => [
        [
		'show' => false,
		'title' => '邀请返利20%',
		'content' => '每邀请一名朋友并成为我们的会员，您将获得邀请佣金奖励(佣金比例20%)，若朋友在草榴加速消费100元，您则可获得返利20元。此返利可用于购买套餐或提现！【快来和我们一起赚钱吧！】',
		'negative' => '',
		'position' => '',
		'positionLink' => ''
	],
	[
		'show' => true,
		'title' => '草榴加速永久官网',
		'content' => '由于政策原因，导致域名很容易被封，这是不可控因素。为了防止失联，请牢记并收藏草榴加速永久地址发布页【 草榴加速.com 】',
		'negative' => '我已知晓',
		'position' => '收藏官网',
		'positionLink' => 'https://cljs.me'
	]
    ],
    
    # 购买套餐下单时的弹窗
    'buyTip' => [
        'show' => true,
        'title' => '温馨提示',
        'content' => '订单支付完成后，请勿点击“关闭订单”，等待订单回调即可，或退出app进程重新查看套餐！',
    ],
    
    # 付款时的弹窗
    'payTip' => [
	'show' => true,
	'title' => '温馨提示',
	'content' => '如已付款切勿关闭此订单，耐心等候付款订单回调即可（通常1~2分钟内）。'
    ],
    
    # 首页网站推荐
    'homeNav' => [
        'show' => true,  # 是否显示
        'title' => '网站推荐',  # 标题
        # 以下列表数量不限可以无限添加，但请注意格式
        'list' => [
            [
                'text' => '草榴加速官网',
                'icon' => 'https://xueshanfeihu.oss-cn-shenzhen.aliyuncs.com/cljs.png',
                'link' => 'https://cljs.me',
            ],
            [
                'text' => 'Google',
                'icon' => 'https://i3.mjj.rip/2023/07/10/46daf515c691dffc8be5389efa01b215.webp',
                'link' => 'https://www.google.com',
            ],
            [
                'text' => 'Telegram',
                'icon' => 'https://simg.doyo.cn/imgfile/bgame/202303/08094239yadd.jpg',
                'link' => 'https://t.me',
            ],
            [
                'text' => 'ChatGPT',
                'icon' => 'https://cdnjson.com/images/2023/07/11/ChatGPT_logo.svg.png',
                'link' => 'https://openai.com',
            ],
            [
                'text' => 'Facebook',
                'icon' => 'https://simg.doyo.cn/imgfile/bgame/202303/07161609vgut.jpg',
                'link' => 'https://www.facebook.com',
            ],
            [
                'text' => 'Instagram',
                'icon' => 'https://simg.doyo.cn/imgfile/bgame/202303/07154226kh8v.jpg',
                'link' => 'https://www.instagram.com',
            ],
            [
                'text' => 'Spotify',
                'icon' => 'https://i3.mjj.rip/2023/07/10/c0e2fa09778c0a0864966f4ad16f5f7d.webp',
                'link' => 'https://www.spotify.com',
            ],
            [
                'text' => 'YouTube',
                'icon' => 'https://simg.doyo.cn/imgfile/bgame/202303/04165047scdv.jpg',
                'link' => 'https://www.youtube.com',
            ],
            [
                'text' => 'Netflix',
                'icon' => 'https://cdnjson.com/images/2023/07/11/e07a41e8afc91b3ff66ddd02e6b8378e786034721acfa948e43de85449c7971b_200.png',
                'link' => 'https://www.netflix.com',
            ],
            [
                'text' => 'Disney+',
                'icon' => 'https://cdnjson.com/images/2023/07/11/eb7202d9c9bfbc97c6f1e644dce1f58f9fbcf193ae9edff9bdda2c088cdbabf0_200.png',
                'link' => 'https://www.disneyplus.com',
            ],
            [
                'text' => '18+',
                'icon' => 'https://cdnjson.com/images/2023/07/11/depositphotos_68110071-stock-illustration-18-age-restriction-sign.webp',
                'link' => 'https://theporndude.com/zh',
            ],
        ]
    ],
];
