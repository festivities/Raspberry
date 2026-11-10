// Package patch applies hash-locked byte tables and plans the APK entries the
// patcher replaces or adds. DEX edits are performed by the dexpatch Java tool
// (tools/dexpatch); this package executes that tool and does not embed LINE
// bytecode.
package patch
