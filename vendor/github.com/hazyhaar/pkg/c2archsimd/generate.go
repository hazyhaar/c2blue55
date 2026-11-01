package c2archsimd

// Recette d'émission des fichiers générés de ce paquet : point unique.
//
// Chaque directive construit le transpileur sgoiter depuis
// c2simd/sgoiter/cmd/sgoiter du même dépôt (go run, compilation mise en cache)
// et émet un fichier depuis sa source C de c2simd/sources/c2archsimd. L'option
// « go -C ../../c2simd » place le transpileur dans son module ; les chemins
// -in et -out sont donc relatifs à c2simd, jamais absolus.
//
// Régénérer, depuis ce répertoire :
//
//	GOEXPERIMENT=simd go generate .
//
// Chaque source tensorielle produit c2_<nom>_gen.go (goexperiment.simd et
// amd64) et son compagnon scalaire c2_<nom>_nosimd_gen.go. Les sources C
// tensorielles définissent chacune, en static, les mêmes assistants
// (fp16_to_fp32, f32_from_bits, __avx2, read_i16) et la même structure
// Block_q8_K ; le paquet Go n'en garde qu'un exemplaire. Propriétaires :
// c2_tensor_dot_q8_0 émet fp16_to_fp32, f32_from_bits et __avx2 ;
// c2_tensor_dot_q4_k_q8_k émet read_i16 ; c2_tensor_gemv2_q6_k_q8_k émet
// Block_q8_K. Les autres directives les écartent par -exclude.
//
// c2archsimd_simd.c écarte c2archsimd_blend_solid_photometric8_avx2, que
// sgoiter refuse (_mm256_i32gather_epi32 hors du catalogue d'abaissement), son
// assistant c2_div255_epu32_avx2, et les types déjà émis par c2archsimd.c.
// c2archsimd_nosimd.go (HasAVX2 et replis des noyaux de c2archsimd_simd.c)
// est écrit à la main, sans générateur : il ne porte plus le suffixe _gen et
// reste hors de cette recette.
//
// exp_f32.c émet ExpFloat32x8 et le balayage C2_exp_f32_array ; il écarte
// ExpFloat32, que sgoiter refuse (fmaf et floorf ne sont pas transpilés) et
// dont le pendant Go scalaire est exp_scalar.go, ainsi que __avx2.
// c2_softmax_grad.c émet les deux noyaux de SoftmaxGradient
// (_c2_softmax_grad_dot, _c2_softmax_grad_wrow) ; il écarte __avx2 et émet la
// boucle vectorielle du produit scalaire, _c2_softmax_grad_dot8, en feuille
// assembleur compilée par gcc -O2 (-asm-leaf, c2_softmax_grad_gen_amd64.s).
// Le souligné initial des noms C garde ces trois fonctions hors de l'API du
// paquet : la feuille ne contrôle pas les bornes de ses tranches.
//
// TestGeneratedFilesReproducible (generate_test.go) lit ces directives, les
// rejoue vers un répertoire temporaire et compare octet par octet chaque
// fichier du paquet qui porte l'en-tête de sgoiter. Modifier la recette se fait
// ici seulement ; aucun fichier généré ne se retouche à la main.
//
// Contrainte de forme, vérifiée par le test : une directive par fichier émis,
// arguments sans guillemets, préfixe exact
// « go -C ../../c2simd run ./sgoiter/cmd/sgoiter ».

//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2archsimd.c -pkg c2archsimd -out ../pkg/c2archsimd/c2archsimd_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2archsimd_simd.c -pkg c2archsimd -exclude c2archsimd_blend_solid_photometric8_avx2,c2_div255_epu32_avx2,c2archsimd_table16_t,c2archsimd_table256_t,c2archsimd_solid_blend_ctx_t -out ../pkg/c2archsimd/c2archsimd_simd_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_dot_q8_0.c -pkg c2archsimd -out ../pkg/c2archsimd/c2_tensor_dot_q8_0_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_dot_q4_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2 -out ../pkg/c2archsimd/c2_tensor_dot_q4_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_dot_q6_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2 -out ../pkg/c2archsimd/c2_tensor_dot_q6_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_dot_q4_k_q8_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2,Block_q8_K -out ../pkg/c2archsimd/c2_tensor_dot_q4_k_q8_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_quantize_q8_k.c -pkg c2archsimd -exclude Block_q8_K -out ../pkg/c2archsimd/c2_quantize_q8_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_gemv2_q4_k_q8_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2,read_i16,Block_q8_K -out ../pkg/c2archsimd/c2_tensor_gemv2_q4_k_q8_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_gemv2_q6_k_q8_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2,read_i16 -out ../pkg/c2archsimd/c2_tensor_gemv2_q6_k_q8_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_gemv4_n4_q8_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2,read_i16,Block_q8_K -asm-leaf c2_tensor_gemv4_n4_q8_k -out ../pkg/c2archsimd/c2_tensor_gemv4_n4_q8_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_tensor_gemv4_n5_q8_k.c -pkg c2archsimd -exclude fp16_to_fp32,f32_from_bits,__avx2,read_i16,Block_q8_K -asm-leaf c2_tensor_gemv4_n5_q8_k -out ../pkg/c2archsimd/c2_tensor_gemv4_n5_q8_k_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/exp_f32.c -pkg c2archsimd -exclude ExpFloat32,__avx2 -out ../pkg/c2archsimd/exp_f32_gen.go
//go:generate go -C ../../c2simd run ./sgoiter/cmd/sgoiter -in sources/c2archsimd/c2_softmax_grad.c -pkg c2archsimd -exclude __avx2 -asm-leaf _c2_softmax_grad_dot8 -out ../pkg/c2archsimd/c2_softmax_grad_gen.go
