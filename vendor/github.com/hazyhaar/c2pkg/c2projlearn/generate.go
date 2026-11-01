// SPDX-License-Identifier: Apache-2.0 OR MIT

package c2projlearn

// Recette d'émission des fichiers générés de ce paquet : point unique.
//
// Chaque directive construit le transpileur sgoiter depuis
// c2simd/sgoiter/cmd/sgoiter du même dépôt (go run, compilation mise en cache)
// et émet <noyau>_gen.go depuis la source C sources/<noyau>.c. L'option
// « go -C ../../../c2simd » place le transpileur dans son module ; les chemins
// -in et -out sont donc relatifs à c2simd, jamais absolus.
//
// Régénérer, depuis ce répertoire :
//
//	go generate .
//
// Les sept sources C portent les noyaux scalaires float32 du projecteur DNS
// appris (strates K-0 à K-3 de l'agent DNS de c2blue55) : convolution 1D,
// mise en commun par maximum sur segments, couche dense, tangente
// hyperbolique, binarisation en code de Hamming, pertes et pas AdamW. Le
// contrat de chaque noyau est écrit en tête de sa source C et dans
// CONTRAT-K0.md ; aucun fichier généré ne se retouche à la main.
//
// TestGeneratedFilesReproducible (generate_test.go) rejoue ces directives vers
// un répertoire temporaire et compare octet par octet chaque fichier du paquet
// qui porte l'en-tête de sgoiter. Les tests *VsCOracle (oracle_c_test.go)
// prouvent la parité contre gcc -O2 -ffp-contract=off ; reference_test.go
// prouve l'exactitude contre des références float64 et des différences finies.
//
// Contrainte de forme, vérifiée par le test : une directive par fichier émis,
// arguments sans guillemets, préfixe exact
// « go -C ../../../c2simd run ./sgoiter/cmd/sgoiter ».

//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/conv1d.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/conv1d_gen.go
//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/maxpool.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/maxpool_gen.go
//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/dense.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/dense_gen.go
//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/activation.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/activation_gen.go
//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/binarize.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/binarize_gen.go
//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/losses.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/losses_gen.go
//go:generate go -C ../../../c2simd run ./sgoiter/cmd/sgoiter -in ../c2simd/c2pkg/c2projlearn/sources/optim.c -pkg c2projlearn -out ../c2simd/c2pkg/c2projlearn/optim_gen.go
