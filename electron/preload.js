/**
 * Preload. Здесь будут IPC-каналы для:
 * - нативного диалога «сохранить .taptuna.zip»;
 * - нативного диалога «выбрать .pcap»;
 * - открытия файла отчёта в системной программе.
 *
 * Пока пустой — весь функционал доступен через HTTP к localhost.
 */
const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("taptunaNative", {
  isElectron: true,
  platform: process.platform,
});