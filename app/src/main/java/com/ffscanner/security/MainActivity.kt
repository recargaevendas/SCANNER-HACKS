package com.ffscanner.security

import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        webView = WebView(this)
        setContentView(webView)

        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.webViewClient = WebViewClient()

        // Registra a interface nativa
        webView.addJavascriptInterface(WebAppInterface(), "FFScannerNative")

        // Carrega a interface web integrada
        webView.loadUrl("file:///android_asset/index.html")
    }

    inner class WebAppInterface {

        @JavascriptInterface
        fun checkPermissionStatus(): String {
            val hasFilePermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Environment.isExternalStorageManager()
            } else {
                checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
            }

            val result = JSONObject()
            result.put("hasStoragePermission", hasFilePermission)
            return result.toString()
        }

        @JavascriptInterface
        fun requestStoragePermission() {
            runOnUiThread {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    try {
                        val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                        intent.data = Uri.parse("package:$packageName")
                        startActivity(intent)
                    } catch (e: Exception) {
                        val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                        startActivity(intent)
                    }
                } else {
                    requestPermissions(
                        arrayOf(android.Manifest.permission.READ_EXTERNAL_STORAGE),
                        1001
                    )
                }
            }
        }

        @JavascriptInterface
        fun checkPackageInstalled(packageName: String): String {
            val result = JSONObject()
            try {
                val pm = packageManager
                val info = pm.getPackageInfo(packageName, 0)
                result.put("installed", true)
                result.put("versionName", info.versionName ?: "Desconhecido")
                result.put("versionCode", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else info.versionCode)
            } catch (e: PackageManager.NameNotFoundException) {
                result.put("installed", false)
            }
            return result.toString()
        }

        @JavascriptInterface
        fun runRealStorageScan(): String {
            val findings = JSONArray()
            val rootsToScan = mutableListOf<File>()

            // Adiciona diretórios públicos acessíveis
            rootsToScan.add(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS))
            rootsToScan.add(Environment.getExternalStorageDirectory())

            val targetKeywords = listOf("xit", "regedit", "bypass", "injector", "h4ck", "modmenu", "headshot", "aimbot")

            for (root in rootsToScan) {
                if (root.exists() && root.isDirectory) {
                    scanDirectory(root, targetKeywords, findings, depth = 0, maxDepth = 4)
                }
            }

            return findings.toString()
        }

        private fun scanDirectory(dir: File, keywords: List<String>, findings: JSONArray, depth: Int, maxDepth: Int) {
            if (depth > maxDepth) return
            val files = dir.listFiles() ?: return

            for (file in files) {
                if (file.isDirectory) {
                    // Pula a pasta /Android/data por causa do bloqueio de leitura do SO
                    if (file.absolutePath.contains("/Android/data") || file.absolutePath.contains("/Android/obb")) {
                        continue
                    }
                    scanDirectory(file, keywords, findings, depth + 1, maxDepth)
                } else {
                    val nameLower = file.name.lowercase()
                    for (kw in keywords) {
                        if (nameLower.contains(kw)) {
                            val item = JSONObject()
                            item.put("name", file.name)
                            item.put("type", "arquivo")
                            item.put("path", file.absolutePath)
                            item.put("reason", "Nome de arquivo contém indicador suspeito: '$kw'")
                            item.put("confidence", "AMARELO")
                            findings.put(item)
                            break
                        }
                    }
                }
            }
        }

        @JavascriptInterface
        fun openFileLocation(filePath: String): Boolean {
            val file = File(filePath)
            if (!file.exists()) return false

            return try {
                val intent = Intent(Intent.ACTION_VIEW)
                val uri = Uri.parse(file.parent)
                intent.setDataAndType(uri, "*/*")
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                startActivity(intent)
                true
            } catch (e: Exception) {
                false
            }
        }
    }
}
