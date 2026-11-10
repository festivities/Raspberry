package patch

// Kind is how an APK zip entry is produced.
type Kind int

const (
	// Replace swaps an existing entry after its input digest matches.
	Replace Kind = iota
	// Add inserts an entry that is not in the stock APK.
	Add
)

// APKEntry is one zip path the patcher must replace or add. Bytes are produced
// elsewhere; this is the map the APK writer should grow into.
type APKEntry struct {
	Name        string
	Kind        Kind
	InputSHA256 string
}

// APKPlan is the v1 entry map: both libgame builds, classes3, plus our dex,
// both hook libraries and the endpoint asset. Other zip entries stay byte
// identical. The APK writer does not apply this yet.
func APKPlan() []APKEntry {
	return []APKEntry{
		{Name: "lib/arm64-v8a/libgame.so", Kind: Replace, InputSHA256: LibgameArm64SHA},
		{Name: "lib/armeabi-v7a/libgame.so", Kind: Replace, InputSHA256: LibgameArmv7SHA},
		{Name: "classes3.dex", Kind: Replace, InputSHA256: Classes3SHA},
		{Name: "classes5.dex", Kind: Add},
		{Name: "lib/arm64-v8a/libraspberry.so", Kind: Add},
		{Name: "lib/armeabi-v7a/libraspberry.so", Kind: Add},
		{Name: "assets/raspberry/endpoint.json", Kind: Add},
	}
}
