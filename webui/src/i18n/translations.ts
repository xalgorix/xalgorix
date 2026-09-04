// Translation dictionaries for the Xalgorix dashboard.
//
// English is the source of truth: every key MUST exist in `en`. Other locales
// may be partial — the `t()` helper falls back to the English string (and then
// to the raw key) when a translation is missing, so a missing entry degrades
// gracefully instead of rendering blank.
//
// Keys are dot-namespaced by surface (nav.*, topbar.*, common.*) so the map
// stays browsable as coverage grows across the app.

export type LanguageCode = "en" | "zh-CN";

// Supported UI languages, in display order. Keep the `code` values in sync with
// the backend config.SupportedLanguages() list.
export const LANGUAGES: { code: LanguageCode; label: string; nativeLabel: string }[] = [
  { code: "en", label: "English", nativeLabel: "English" },
  { code: "zh-CN", label: "Simplified Chinese", nativeLabel: "简体中文" },
];

export const DEFAULT_LANGUAGE: LanguageCode = "en";

export function isLanguageCode(value: string | null | undefined): value is LanguageCode {
  return value === "en" || value === "zh-CN";
}

// Normalize a raw code/name (e.g. from the backend or localStorage) to a
// supported LanguageCode, falling back to English for anything unknown.
export function normalizeLanguage(raw: string | null | undefined): LanguageCode {
  if (!raw) return DEFAULT_LANGUAGE;
  const key = raw.trim().toLowerCase();
  if (key === "en" || key === "en-us" || key === "english") return "en";
  if (
    key === "zh" ||
    key === "zh-cn" ||
    key === "zh_cn" ||
    key === "zh-hans" ||
    key === "chinese" ||
    key === "simplified chinese"
  ) {
    return "zh-CN";
  }
  return DEFAULT_LANGUAGE;
}

type Dict = Record<string, string>;

const en: Dict = {
  // Sidebar navigation
  "nav.overview": "Overview",
  "nav.newScan": "New Scan",
  "nav.scans": "Scans",
  "nav.schedules": "Schedules",
  "nav.instances": "Instances",
  "nav.findings": "Findings",
  "nav.live": "Live Feed",
  "nav.email": "Email Triage",
  "nav.reports": "Reports",
  "nav.integrations": "Integrations",
  "nav.settings": "Settings",
  "sidebar.localScanner": "Local scanner",
  "sidebar.commandHint": "Ctrl+K for actions",
  "sidebar.github": "GitHub",
  "sidebar.githubTitle": "View Xalgorix on GitHub",
  "sidebar.securityScanner": "security scanner",
  "sidebar.navigation": "Main navigation",

  // Topbar
  "topbar.searchLong": "Search scans, findings, actions…",
  "topbar.searchShort": "Search…",
  "topbar.openPalette": "Open command palette",
  "topbar.toggleMenu": "Toggle menu",
  "topbar.newScan": "New Scan",
  "topbar.stopAll": "Stop all",
  "topbar.scanning": "Scanning",
  "topbar.activeScan": "active scan",
  "topbar.activeScans": "active scans",
  "topbar.language": "Language",
  "topbar.theme": "Theme",
  "theme.light": "Light",
  "theme.dark": "Dark",
  "theme.system": "System",

  // Severity labels (shared across findings, badges, tables)
  "severity.critical": "Critical",
  "severity.high": "High",
  "severity.medium": "Medium",
  "severity.low": "Low",
  "severity.info": "Info",

  // Scan status labels (shared across scans, instances, pills)
  "status.running": "Running",
  "status.pending": "Pending",
  "status.paused": "Paused",
  "status.saved": "Saved",
  "status.completed": "Completed",
  "status.finished": "Completed",
  "status.stopped": "Stopped",
  "status.failed": "Failed",
  "status.unknown": "Unknown",

  // Common
  "common.loading": "Loading…",
  "common.save": "Save",
  "common.cancel": "Cancel",
  "common.open": "Open",
  "common.delete": "Delete",
  "common.somethingWrong": "Something went wrong",
  "common.findings": "findings",
  "common.tokens": "tokens",

  // States
  "states.noData": "No data",

  // Reports page
  "reports.title": "Reports",
  "reports.subtitle": "PDF reports for every completed scan. Generated on demand by the server.",
  "reports.searchPlaceholder": "Search reports by target or scan ID…",
  "reports.emptyTitle": "No reports yet",
  "reports.emptyDescription": "Run a scan and a PDF report will be available here.",
  "reports.confirmDelete": "Permanently delete this report and scan record?",

  // Overview page
  "overview.title": "Overview",
  "overview.recentScans": "Recent Scans",
  "overview.liveActivity": "Live Activity",
  "overview.systemHealth": "System Health",
  "overview.criticalFindings": "Critical Findings",
  "overview.findingMix": "Finding Mix",
  "overview.operations": "Operations",
  "overview.latestScan": "Latest scan",

  // Findings page
  "findings.title": "Findings",
  "findings.allSeverities": "All severities",

  // Scans page
  "scans.title": "Scans",
  "scans.subtitle": "All historical and in-flight scans.",
  "scans.allStatuses": "All statuses",
  "scans.col.findings": "Findings",
  "scans.col.tokens": "Tokens",
  "scans.col.started": "Started",
  "scans.col.status": "Status",
  "scans.col.actions": "Actions",

  // New Scan page
  "newScan.back": "Back",
  "newScan.heading": "Start a new scan",
  "newScan.section.targets": "Targets",
  "newScan.label.targets": "Targets *",
  "newScan.label.displayName": "Display name (optional)",
  "newScan.section.securityContext": "Security context (optional)",
  "newScan.section.authAccess": "Authenticated access (optional)",
  "newScan.label.authSession": "Authenticated session",
  "newScan.label.secondAccount": "Second account (for IDOR/BOLA proof)",
  "newScan.section.targetAccess": "Target access",
  "newScan.section.reportBranding": "Report branding",
  "newScan.label.brandName": "Target brand name",
  "newScan.label.brandLogo": "Target brand logo",
  "newScan.section.scanMode": "Scan mode",
  "newScan.section.refinement": "Refinement",
  "newScan.label.severityFilter": "Severity filter",
  "newScan.label.customInstruction": "Custom instruction",
  "newScan.label.modelOverride": "Model override",
  "newScan.label.providerProfile": "Provider profile",
  "newScan.btn.saveForLater": "Save for later",
  "newScan.btn.startScan": "Start scan",

  // Schedules page
  "schedules.title": "Schedules",
  "schedules.subtitle": "Manage automated recurring scans running on configured intervals.",
  "schedules.new": "New schedule",
  "schedules.create": "Create schedule",
  "schedules.emptyTitle": "No scheduled scans",
  "schedules.emptyDescription": "Automate recurring testing across your target landscape.",
  "schedules.never": "Never",
  "schedules.label.name": "Schedule Name *",
  "schedules.label.interval": "Frequency Interval *",
  "schedules.label.runAt": "Run at",
  "schedules.label.timezone": "Timezone",
  "schedules.label.targets": "Targets *",
  "schedules.label.scanMode": "Scan Mode",
  "schedules.label.providerProfile": "Provider profile",
  "schedules.label.reconAccess": "Recon Access",
  "schedules.label.testingAccess": "Testing Access",
  "schedules.label.modelOverride": "Model override",
  "schedules.label.severityFilter": "Severity filter",
  "schedules.label.companyName": "Branding Company Name",
  "schedules.label.brandLogo": "Target Brand Logo",
  "schedules.saving": "Saving…",
  "schedules.saveSchedule": "Save schedule",
  "schedules.runNow": "Run now",
  "schedules.editSettings": "Edit settings",
  "schedules.deleteSchedule": "Delete schedule",

  // Instances page
  "instances.title": "Instances",
  "instances.subtitle": "Active scan instances and global host pressure. Completed scans are historical records.",
  "instances.allStatuses": "All statuses",
  "instances.allModes": "All modes",
  "instances.emptyTitle": "No instances match",
  "instances.emptyDescription": "Adjust the search or filters to see more.",
  "instances.loadError": "Could not load instances",

  // Integrations page
  "integrations.title": "Integrations",
  "integrations.category.AI": "AI",
  "integrations.category.Email": "Email",
  "integrations.category.Notifications": "Notifications",
  "integrations.category.Engagement": "Engagement",
  "integrations.connected": "Connected",
  "integrations.notConnected": "Not connected",

  // Live page
  "live.title": "Live Feed",

  // Email triage page
  "email.title": "Email Triage",
  "email.subtitle": "Live AgentMail events and ingestion status.",
  "email.pod": "AgentMail pod",
  "email.apiKey": "API key",
  "email.status": "Status",
  "email.notConfigured": "not configured",
  "email.set": "set",
  "email.missing": "missing",
  "email.listening": "listening",
  "email.setupRequired": "setup required",

  // Scan detail page
  "scanDetail.phaseProgress": "Phase progress",
  "scanDetail.riskOverview": "Risk overview",
  "scanDetail.wildcardCoverage": "Wildcard coverage",
  "scanDetail.tab.findings": "Findings",
  "scanDetail.tab.events": "Events",
  "scanDetail.tab.subdomains": "Subdomains",
  "scanDetail.tab.config": "Config",
  "scanDetail.guideScan": "Guide this scan",

  // Settings page
  "settings.title": "Settings",
  "settings.tab.llm": "LLM",
  "settings.tab.engagement": "Engagement",
  "settings.tab.notifications": "Notifications",
  "settings.tab.email": "Email",
  "settings.tab.environment": "Environment",
  "settings.tab.account": "Account",
  "settings.card.llmProvider": "LLM provider",
  "settings.card.rateLimits": "Rate limits",
  "settings.card.discord": "Discord notifications",
  "settings.card.telegram": "Telegram notifications",
  "settings.card.agentMail": "AgentMail",
  "settings.card.account": "Account",
  "settings.account.desc": "Session and access.",
  "settings.savedIndicator": "Saved",
  "settings.searchVariables": "Search variables...",
};

const zhCN: Dict = {
  // Sidebar navigation
  "nav.overview": "概览",
  "nav.newScan": "新建扫描",
  "nav.scans": "扫描任务",
  "nav.schedules": "计划任务",
  "nav.instances": "实例",
  "nav.findings": "漏洞发现",
  "nav.live": "实时动态",
  "nav.email": "邮件分诊",
  "nav.reports": "报告",
  "nav.integrations": "集成",
  "nav.settings": "设置",
  "sidebar.localScanner": "本地扫描器",
  "sidebar.commandHint": "按 Ctrl+K 打开操作面板",
  "sidebar.github": "GitHub",
  "sidebar.githubTitle": "在 GitHub 上查看 Xalgorix",
  "sidebar.securityScanner": "安全扫描器",
  "sidebar.navigation": "主导航",

  // Topbar
  "topbar.searchLong": "搜索扫描、漏洞、操作…",
  "topbar.searchShort": "搜索…",
  "topbar.openPalette": "打开命令面板",
  "topbar.toggleMenu": "切换菜单",
  "topbar.newScan": "新建扫描",
  "topbar.stopAll": "全部停止",
  "topbar.scanning": "正在扫描",
  "topbar.activeScan": "个进行中的扫描",
  "topbar.activeScans": "个进行中的扫描",
  "topbar.language": "语言",
  "topbar.theme": "主题",
  "theme.light": "浅色",
  "theme.dark": "深色",
  "theme.system": "跟随系统",

  // Severity labels
  "severity.critical": "严重",
  "severity.high": "高危",
  "severity.medium": "中危",
  "severity.low": "低危",
  "severity.info": "信息",

  // Scan status labels
  "status.running": "运行中",
  "status.pending": "等待中",
  "status.paused": "已暂停",
  "status.saved": "已保存",
  "status.completed": "已完成",
  "status.finished": "已完成",
  "status.stopped": "已停止",
  "status.failed": "已失败",
  "status.unknown": "未知",

  // Common
  "common.loading": "加载中…",
  "common.save": "保存",
  "common.cancel": "取消",
  "common.open": "打开",
  "common.delete": "删除",
  "common.somethingWrong": "出错了",
  "common.findings": "个漏洞",
  "common.tokens": "个令牌",

  // States
  "states.noData": "暂无数据",

  // Reports page
  "reports.title": "报告",
  "reports.subtitle": "为每个已完成的扫描生成 PDF 报告，由服务器按需生成。",
  "reports.searchPlaceholder": "按目标或扫描 ID 搜索报告…",
  "reports.emptyTitle": "暂无报告",
  "reports.emptyDescription": "运行一次扫描后，PDF 报告将显示在此处。",
  "reports.confirmDelete": "确定要永久删除此报告和扫描记录吗？",

  // Overview page
  "overview.title": "概览",
  "overview.recentScans": "最近扫描",
  "overview.liveActivity": "实时活动",
  "overview.systemHealth": "系统健康",
  "overview.criticalFindings": "严重漏洞",
  "overview.findingMix": "漏洞分布",
  "overview.operations": "运行统计",
  "overview.latestScan": "最近一次扫描",

  // Findings page
  "findings.title": "漏洞发现",
  "findings.allSeverities": "全部严重级别",

  // Scans page
  "scans.title": "扫描任务",
  "scans.subtitle": "所有历史扫描与进行中的扫描。",
  "scans.allStatuses": "全部状态",
  "scans.col.findings": "漏洞数",
  "scans.col.tokens": "令牌数",
  "scans.col.started": "开始时间",
  "scans.col.status": "状态",
  "scans.col.actions": "操作",

  // New Scan page
  "newScan.back": "返回",
  "newScan.heading": "开始新扫描",
  "newScan.section.targets": "目标",
  "newScan.label.targets": "目标 *",
  "newScan.label.displayName": "显示名称（可选）",
  "newScan.section.securityContext": "安全上下文（可选）",
  "newScan.section.authAccess": "已认证访问（可选）",
  "newScan.label.authSession": "已认证会话",
  "newScan.label.secondAccount": "第二个账户（用于 IDOR/BOLA 验证）",
  "newScan.section.targetAccess": "目标访问",
  "newScan.section.reportBranding": "报告品牌",
  "newScan.label.brandName": "目标品牌名称",
  "newScan.label.brandLogo": "目标品牌 Logo",
  "newScan.section.scanMode": "扫描模式",
  "newScan.section.refinement": "细化设置",
  "newScan.label.severityFilter": "严重级别筛选",
  "newScan.label.customInstruction": "自定义指令",
  "newScan.label.modelOverride": "模型覆盖",
  "newScan.label.providerProfile": "提供商配置",
  "newScan.btn.saveForLater": "稍后保存",
  "newScan.btn.startScan": "开始扫描",

  // Schedules page
  "schedules.title": "计划任务",
  "schedules.subtitle": "管理按配置的时间间隔运行的自动化周期性扫描。",
  "schedules.new": "新建计划",
  "schedules.create": "创建计划",
  "schedules.emptyTitle": "暂无计划扫描",
  "schedules.emptyDescription": "为你的目标范围设置自动化周期性测试。",
  "schedules.never": "从未",
  "schedules.label.name": "计划名称 *",
  "schedules.label.interval": "频率间隔 *",
  "schedules.label.runAt": "运行时间",
  "schedules.label.timezone": "时区",
  "schedules.label.targets": "目标 *",
  "schedules.label.scanMode": "扫描模式",
  "schedules.label.providerProfile": "提供商配置",
  "schedules.label.reconAccess": "侦察访问",
  "schedules.label.testingAccess": "测试访问",
  "schedules.label.modelOverride": "模型覆盖",
  "schedules.label.severityFilter": "严重级别筛选",
  "schedules.label.companyName": "品牌公司名称",
  "schedules.label.brandLogo": "目标品牌 Logo",
  "schedules.saving": "保存中…",
  "schedules.saveSchedule": "保存计划",
  "schedules.runNow": "立即运行",
  "schedules.editSettings": "编辑设置",
  "schedules.deleteSchedule": "删除计划",

  // Instances page
  "instances.title": "实例",
  "instances.subtitle": "活动扫描实例与全局主机负载。已完成的扫描为历史记录。",
  "instances.allStatuses": "全部状态",
  "instances.allModes": "全部模式",
  "instances.emptyTitle": "没有匹配的实例",
  "instances.emptyDescription": "请调整搜索或筛选条件以查看更多。",
  "instances.loadError": "无法加载实例",

  // Integrations page
  "integrations.title": "集成",
  "integrations.category.AI": "AI",
  "integrations.category.Email": "邮件",
  "integrations.category.Notifications": "通知",
  "integrations.category.Engagement": "测试参数",
  "integrations.connected": "已连接",
  "integrations.notConnected": "未连接",

  // Live page
  "live.title": "实时动态",

  // Email triage page
  "email.title": "邮件分诊",
  "email.subtitle": "实时 AgentMail 事件与接收状态。",
  "email.pod": "AgentMail Pod",
  "email.apiKey": "API 密钥",
  "email.status": "状态",
  "email.notConfigured": "未配置",
  "email.set": "已设置",
  "email.missing": "缺失",
  "email.listening": "监听中",
  "email.setupRequired": "需要配置",

  // Scan detail page
  "scanDetail.phaseProgress": "阶段进度",
  "scanDetail.riskOverview": "风险概览",
  "scanDetail.wildcardCoverage": "通配符覆盖",
  "scanDetail.tab.findings": "漏洞发现",
  "scanDetail.tab.events": "事件",
  "scanDetail.tab.subdomains": "子域名",
  "scanDetail.tab.config": "配置",
  "scanDetail.guideScan": "引导此扫描",

  // Settings page
  "settings.title": "设置",
  "settings.tab.llm": "大模型",
  "settings.tab.engagement": "测试参数",
  "settings.tab.notifications": "通知",
  "settings.tab.email": "邮件",
  "settings.tab.environment": "环境变量",
  "settings.tab.account": "账户",
  "settings.card.llmProvider": "大模型提供商",
  "settings.card.rateLimits": "速率限制",
  "settings.card.discord": "Discord 通知",
  "settings.card.telegram": "Telegram 通知",
  "settings.card.agentMail": "AgentMail",
  "settings.card.account": "账户",
  "settings.account.desc": "会话与访问权限。",
  "settings.savedIndicator": "已保存",
  "settings.searchVariables": "搜索变量…",
};

export const translations: Record<LanguageCode, Dict> = {
  en,
  "zh-CN": zhCN,
};
