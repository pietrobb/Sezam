package sk.sezam.sezam_mobile

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream

// FlutterFragmentActivity is required by the biometric prompt.
class MainActivity : FlutterFragmentActivity() {
    // Files outside the app sandbox go through the system document picker
    // (lockout review M4): no storage permission, the user picks the place.
    private var pendingSave: Pair<ByteArray, MethodChannel.Result>? = null
    private var pendingOpen: Pair<Int, MethodChannel.Result>? = null

    private val createDocument =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
            val (bytes, result) = pendingSave ?: return@registerForActivityResult
            pendingSave = null
            if (uri == null) {
                result.success(false)
                return@registerForActivityResult
            }
            try {
                val stream = contentResolver.openOutputStream(uri, "wt")
                    ?: throw java.io.IOException("Cannot write the chosen file")
                stream.use { it.write(bytes) }
                result.success(true)
            } catch (e: Exception) {
                result.error("write_failed", e.message, null)
            }
        }

    private val openDocument =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            val (maxBytes, result) = pendingOpen ?: return@registerForActivityResult
            pendingOpen = null
            if (uri == null) {
                result.success(null)
                return@registerForActivityResult
            }
            try {
                val input = contentResolver.openInputStream(uri)
                    ?: throw java.io.IOException("Cannot read the chosen file")
                val out = ByteArrayOutputStream()
                input.use {
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val n = it.read(buffer)
                        if (n < 0) break
                        if (out.size() + n > maxBytes) throw java.io.IOException("File is too large")
                        out.write(buffer, 0, n)
                    }
                }
                result.success(out.toByteArray())
            } catch (e: Exception) {
                result.error("read_failed", e.message, null)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Secrets must not appear in screenshots, screen recordings or the
        // recent-apps thumbnail.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "sk.sezam/clipboard")
            .setMethodCallHandler { call, result ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                when (call.method) {
                    "setSensitive" -> {
                        val clip = ClipData.newPlainText("", call.argument<String>("text") ?: "")
                        // Hidden from the Android 13+ copy preview and IME suggestions.
                        if (Build.VERSION.SDK_INT >= 24) {
                            clip.description.extras = PersistableBundle().apply {
                                putBoolean(
                                    if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE
                                    else "android.content.extra.IS_SENSITIVE",
                                    true,
                                )
                            }
                        }
                        clipboard.setPrimaryClip(clip)
                        result.success(null)
                    }
                    "clear" -> {
                        // Writing is allowed without focus on Android 10+; only reading is not.
                        if (Build.VERSION.SDK_INT >= 28) {
                            clipboard.clearPrimaryClip()
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "sk.sezam/files")
            .setMethodCallHandler { call, result ->
                if (pendingSave != null || pendingOpen != null) {
                    result.error("busy", "A file picker is already open", null)
                    return@setMethodCallHandler
                }
                when (call.method) {
                    "saveDocument" -> {
                        val bytes = call.argument<ByteArray>("bytes")
                        if (bytes == null) {
                            result.error("bad_args", "No content", null)
                        } else {
                            pendingSave = Pair(bytes, result)
                            createDocument.launch(call.argument<String>("name") ?: "sezam.json")
                        }
                    }
                    "openDocument" -> {
                        pendingOpen = Pair(call.argument<Int>("max_bytes") ?: (64 * 1024 * 1024), result)
                        openDocument.launch(arrayOf(call.argument<String>("mime") ?: "*/*", "*/*"))
                    }
                    else -> result.notImplemented()
                }
            }
    }
}
