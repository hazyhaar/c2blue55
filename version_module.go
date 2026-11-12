package c2blue55

// versionModule est la version du produit c2blue55, sous la forme
// majeur.mineur.correctif : celle que citent les sections datées des README.
// Ce n'est pas une version de module Go : le chemin du module ne porte pas de
// suffixe /v8 et le dépôt n'est pas étiqueté sous ce numéro.
const versionModule = "8.3.0"

// VersionModule rend la version du produit c2blue55, sous la forme
// majeur.mineur.correctif, sans préfixe.
func VersionModule() string {
	return versionModule
}
