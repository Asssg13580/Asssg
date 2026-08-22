package com.example.iqoochecker

import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.iqoochecker.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.time.LocalDate
import java.time.format.DateTimeFormatter

// ---------- 数据模型 ----------
enum class RiskLevel(val label: String, val color: Int, val rank: Int) {
    LOW("低", Color.parseColor("#2E7D32"), 1),
    MEDIUM("中", Color.parseColor("#F57C00"), 2),
    HIGH("高", Color.parseColor("#D32F2F"), 3),
    CRITICAL("严重", Color.parseColor("#B71C1C"), 4);
    companion object {
        fun maxOf(a: RiskLevel, b: RiskLevel) = if (a.rank >= b.rank) a else b
    }
}

data class RuleResult(
    val name: String,
    val vulnerable: Boolean,
    val detail: String,
    val severity: RiskLevel
)

data class DeviceInfo(
    val model: String?,
    val boardPlatform: String?,
    val hardware: String?,
    val socModel: String?,
    val securityPatch: String?,
    val buildDisplayId: String?,
    val buildIncremental: String?,
    val cpuInfo: String?
) {
    fun securityPatchDate(): LocalDate? = try {
        securityPatch?.trim()?.let {
            LocalDate.parse(it, DateTimeFormatter.ofPattern("yyyy-MM-dd"))
        }
    } catch (e: Exception) { null }
}

// ---------- Shizuku 封装 ----------
data class ShellResult(val exitCode: Int, val stdout: String, val stderr: String) {
    val ok: Boolean get() = exitCode == 0
}

object ShizukuManager {
    fun isRunning(): Boolean = try { Shizuku.pingBinder() } catch (e: Throwable) { false }
    fun hasPermission(): Boolean =
        Shizuku.isPreV11() || Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
}

object ShizukuShell {
    suspend fun exec(vararg cmd: String): ShellResult = withContext(Dispatchers.IO) {
        try {
            val p = Shizuku.newProcess(cmd, null, null)
            val out = p.inputStream.bufferedReader().readText()
            val err = p.errorStream.bufferedReader().readText()
            val code = p.waitFor()
            ShellResult(code, out.trim(), err.trim())
        } catch (e: Exception) {
            ShellResult(-1, "", e.message ?: "exec failed")
        }
    }
    suspend fun cat(path: String) = exec("cat", path)
    suspend fun grep(path: String, keyword: String) =
        exec("sh", "-c", "grep -w '$keyword' '$path' 2>/dev/null || true")
    suspend fun getProp(key: String): String? =
        exec("getprop", key).stdout.ifEmpty { null }
    suspend fun getProps(keys: List<String>): Map<String, String?> = coroutineScope {
        keys.map { k -> async { k to getProp(k) } }.awaitAll().toMap()
    }
}

// ---------- 设备信息读取 ----------
object DeviceInfoReader {
    private val PROPS = listOf(
        "ro.product.model",
        "ro.product.vendor.model",
        "ro.board.platform",
        "ro.hardware",
        "ro.soc.model",
        "ro.build.version.security_patch",
        "ro.build.display.id",
        "ro.build.version.incremental"
    )
    suspend fun read(): DeviceInfo {
        val values = ShizukuShell.getProps(PROPS)
        val cpu = ShizukuShell.cat("/proc/cpuinfo")
        return DeviceInfo(
            model = values["ro.product.model"] ?: values["ro.product.vendor.model"],
            boardPlatform = values["ro.board.platform"],
            hardware = values["ro.hardware"],
            socModel = values["ro.soc.model"],
            securityPatch = values["ro.build.version.security_patch"],
            buildDisplayId = values["ro.build.display.id"],
            buildIncremental = values["ro.build.version.incremental"],
            cpuInfo = if (cpu.ok) cpu.stdout.ifEmpty { null } else null
        )
    }
}

// ---------- 前置条件检查 ----------
data class ConditionCheck(val name: String, val passed: Boolean)

object DeviceChecker {
    const val TARGET_BUILD = "PD2520D_A_16.0.24.6.W10.V000L1"
    private val PATCH_BASE = LocalDate.of(2025, 7, 1)

    fun isTargetModel(info: DeviceInfo) = info.model?.contains("Neo11", ignoreCase = true) == true

    fun isTargetPlatform(info: DeviceInfo): Boolean {
        val candidates = listOf(info.boardPlatform, info.hardware, info.socModel, info.cpuInfo)
        return candidates.any { it?.contains("SM8750", ignoreCase = true) == true } ||
                candidates.any { it?.contains("sun", ignoreCase = true) == true } ||
                candidates.any { it?.contains("8750", ignoreCase = true) == true }
    }

    fun isPatchBefore(info: DeviceInfo): Boolean {
        val patch = info.securityPatchDate() ?: return false
        return patch.isBefore(PATCH_BASE)
    }

    fun isTargetBuild(info: DeviceInfo) =
        info.buildDisplayId == TARGET_BUILD || info.buildIncremental == TARGET_BUILD

    fun evaluate(info: DeviceInfo) = listOf(
        ConditionCheck("设备型号 iQOO Neo11", isTargetModel(info)),
        ConditionCheck("处理器 骁龙8至尊版 (SM8750)", isTargetPlatform(info)),
        ConditionCheck("安全补丁早于 2025-07-01", isPatchBefore(info)),
        ConditionCheck("系统版本 $TARGET_BUILD", isTargetBuild(info))
    )
}

// ---------- 漏洞规则接口 ----------
interface VulnerabilityRule {
    val name: String
    suspend fun check(): RuleResult
}

/** 文件权限检查规则 */
class FilePermissionRule(private val path: String) : VulnerabilityRule {
    override val name = "文件权限检查 ($path)"
    override suspend fun check(): RuleResult {
        val res = ShizukuShell.exec("ls", "-ldZ", path)
        if (!res.ok) return RuleResult(name, false, "无法访问（可能不存在）", RiskLevel.LOW)
        val parts = res.stdout.split(Regex("\\s+"))
        val perms = parts.getOrNull(0) ?: "?"
        val owner = parts.getOrNull(2) ?: "?"
        val worldWritable = Regex("^.[rwxs-][rwxs-][rwxs-][rwxs-][rwxs-][rwxs-][rwxs-]w[stx-]$").containsMatchIn(perms)
        return RuleResult(name, worldWritable, "权限=$perms 属主=$owner", if (worldWritable) RiskLevel.HIGH else RiskLevel.LOW)
    }
}

/** 系统属性/配置检查规则 */
class SystemPropRule(
    private val propKey: String,
    private val badValue: String? = null,
    private val mustExist: Boolean = true
) : VulnerabilityRule {
    override val name = "配置检查 ($propKey)"
    override suspend fun check(): RuleResult {
        val value = ShizukuShell.getProp(propKey)
        val hit = when {
            value == null -> false
            badValue != null -> value == badValue
            else -> mustExist
        }
        return RuleResult(name, hit, "$propKey = ${value ?: "(空)"}", if (hit) RiskLevel.MEDIUM else RiskLevel.LOW)
    }
}

/** 内核符号检查规则 */
class KernelSymbolRule(private val symbol: String) : VulnerabilityRule {
    override val name = "内核符号检查 ($symbol)"
    override suspend fun check(): RuleResult {
        val res = ShizukuShell.grep("/proc/kallsyms", symbol)
        val found = res.ok && res.stdout.isNotBlank()
        return RuleResult(name, found, if (found) "符号存在" else "未找到", if (found) RiskLevel.CRITICAL else RiskLevel.LOW)
    }
}

/** 文件内容提取规则（只读，不判风险，仅展示） */
class FileContentExtractRule(
    private val path: String,
    private val maxLines: Int = 20
) : VulnerabilityRule {
    override val name = "提取文件内容 ($path)"
    override suspend fun check(): RuleResult {
        val res = ShizukuShell.cat(path)
        if (!res.ok) return RuleResult(name, false, "无法读取文件", RiskLevel.LOW)
        val lines = res.stdout.lines()
        val preview = lines.take(maxLines).joinToString("\n")
        val detail = if (lines.size > maxLines) {
            "共 ${lines.size} 行，前 $maxLines 行：\n$preview"
        } else {
            "共 ${lines.size} 行：\n$preview"
        }
        return RuleResult(name, false, detail, RiskLevel.LOW)
    }
}

object VulnerabilityRules {
    fun getDefault(): List<VulnerabilityRule> = listOf(
        // TODO: 在这里填入原作者提供的漏洞特征
        // 示例：
        // FilePermissionRule("/system/bin/某文件"),
        // SystemPropRule("某属性名", badValue = "1"),
        // KernelSymbolRule("某符号"),
        // FileContentExtractRule("/proc/version", 10)
    )
}

// ---------- 风险评估 ----------
data class Assessment(val level: RiskLevel, val summary: String, val remediation: List<String>)

object RiskAssessor {
    fun assess(results: List<RuleResult>): Assessment {
        val vulnerable = results.filter { it.vulnerable }
        return if (vulnerable.isEmpty()) {
            Assessment(RiskLevel.LOW, "未发现漏洞特征，当前固件风险较低", listOf("仍建议保持系统更新至最新安全补丁"))
        } else {
            val level = vulnerable.fold(RiskLevel.LOW) { acc, r -> RiskLevel.maxOf(acc, r.severity) }
            Assessment(level, "检测到 ${vulnerable.size} 项漏洞特征", listOf("立即升级系统至安全补丁 ≥ 2025-07-01 的固件版本"))
        }
    }
}

// ---------- 主界面 ----------
class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val permissionRequestCode = 114514

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        showDisclaimerIfNeeded()
        binding.btnCheck.setOnClickListener { startCheck() }
    }

    private fun showDisclaimerIfNeeded() {
        val prefs = getSharedPreferences("checker", MODE_PRIVATE)
        if (prefs.getBoolean("disclaimer_accepted", false)) return
        AlertDialog.Builder(this)
            .setTitle("免责声明")
            .setMessage("仅限授权测试或本人设备，使用者需自行承担法律责任。\n\n本工具仅执行只读检测，不包含任何提权操作或恶意代码。")
            .setCancelable(false)
            .setPositiveButton("同意") { _, _ -> prefs.edit().putBoolean("disclaimer_accepted", true).apply() }
            .setNegativeButton("拒绝") { _, _ -> finish() }
            .show()
    }

    private fun startCheck() {
        if (!ShizukuManager.isRunning()) {
            toast("未检测到 Shizuku 服务，请先启动 Shizuku 并授权本应用")
            return
        }
        if (!ShizukuManager.hasPermission()) {
            Shizuku.requestPermission(permissionRequestCode)
            return
        }
        binding.btnCheck.isEnabled = false
        lifecycleScope.launch {
            try { runCheck() } finally { binding.btnCheck.isEnabled = true }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == permissionRequestCode) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                toast("Shizuku 授权成功")
                startCheck()
            } else {
                toast("未授予 Shizuku 权限")
            }
        }
    }

    private suspend fun runCheck() {
        binding.tvStatus.text = "正在读取设备信息..."
        val info = DeviceInfoReader.read()
        binding.tvLog.append("型号: ${info.model}\n")
        binding.tvLog.append("platform: ${info.boardPlatform} / hardware: ${info.hardware} / soc: ${info.socModel}\n")
        binding.tvLog.append("安全补丁: ${info.securityPatch}\n")
        binding.tvLog.append("版本号: ${info.buildDisplayId} / ${info.buildIncremental}\n\n")

        val checks = DeviceChecker.evaluate(info)
        binding.tvConditions.text = checks.joinToString("\n") { "${if (it.passed) "✔" else "✘"} ${it.name}" }
        binding.tvConditions.visibility = android.view.View.VISIBLE
        checks.forEach { binding.tvLog.append("${if (it.passed) "✔" else "✘"} ${it.name}\n") }

        if (checks.any { !it.passed }) {
            binding.tvResult.text = "当前设备不符合测试条件，已退出"
            binding.tvResult.visibility = android.view.View.VISIBLE
            binding.tvRisk.text = "不适用"
            binding.tvRisk.setTextColor(Color.parseColor("#757575"))
            binding.tvRisk.visibility = android.view.View.VISIBLE
            binding.tvLog.append("\n检测终止\n")
            binding.tvLog.visibility = android.view.View.VISIBLE
            return
        }

        binding.tvLog.append("\n设备符合条件，开始漏洞特征检测...\n")
        val results = VulnerabilityRules.getDefault().map { it.check() }
        results.forEach { r ->
            binding.tvLog.append("${if (r.vulnerable) "⚠" else "✓"} ${r.name}：${r.detail}\n")
        }
        val assessment = RiskAssessor.assess(results)
        binding.tvResult.text = assessment.summary
        binding.tvResult.visibility = android.view.View.VISIBLE
        binding.tvRisk.text = "风险等级：${assessment.level.label}"
        binding.tvRisk.setTextColor(assessment.level.color)
        binding.tvRisk.visibility = android.view.View.VISIBLE
        binding.tvAdvice.text = assessment.remediation.joinToString("\n")
        binding.tvAdvice.visibility = android.view.View.VISIBLE
        binding.tvLog.visibility = android.view.View.VISIBLE
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
