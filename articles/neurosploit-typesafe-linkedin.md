# Decisão calibrada em segurança ofensiva: o que aconteceu quando plugei o TypeSafe System One dentro de um harness de pentest autônomo

Existe um problema silencioso em quase todo harness de pentest movido a LLM. O modelo é excelente para gerar texto, encadear raciocínio e escrever payload, mas péssimo para entregar uma decisão que o software consiga consumir direto. Quando o pipeline pergunta "isso é um finding confirmado ou não", "qual a severidade real disso", "esse agente vale a pena rodar contra essa superfície", a resposta volta em prosa. Aí o harness precisa interpretar essa prosa, e é exatamente nesse ponto que nasce o falso positivo, o Critical inflado e o relatório que o cliente não acredita.

Neste artigo eu mostro, passo a passo, o que aconteceu quando conectei o TypeSafe System One ao NeuroSploit, um harness de pentest autônomo escrito em Rust. Vou explicar primeiro o que é o TypeSafe, o modelo System One e o Jev, depois o que é o NeuroSploit, em seguida como configurar os dois juntos na prática, e por fim um benchmark real com e sem TypeSafe contra o mesmo alvo, com os números, os ganhos, os ajustes que precisei fazer e uma limitação honesta que o próprio experimento expôs.

---

## Parte 1: o que é o TypeSafe AI, o modelo System One e o Jev

O TypeSafe AI parte de uma tese simples e incomum. A maioria dos modelos de linguagem foi desenhada para produzir texto legível por humanos. Software não quer texto, quer decisão tipada. O TypeSafe chama sua família de modelos de System One, em oposição direta ao raciocínio lento e verboso. A ideia é a de uma decisão rápida, focada e estruturada, do tipo que o código consegue ramificar em cima sem precisar interpretar nada.

O Jev é o modelo principal dessa família, o primeiro System One deles. A diferença central é esta: o Jev não gera texto, não escreve explicação, não devolve um parágrafo. Ele avalia perguntas tipadas contra um estado e devolve um resultado estruturado, com distribuições de probabilidade calibradas. Você entrega um estado (por exemplo, a evidência de um finding) e uma pergunta, e recebe de volta um número em que o código pode confiar.

A API expõe três primitivas, e cada uma responde a uma classe de pergunta diferente:

1. **Choice**: escolha uma opção dentro de um conjunto definido. Devolve a opção escolhida, um mapa de probabilidades por opção e uma confiança. É o que você usa para "confirmado, precisa de revisão ou rejeitado".
2. **Score**: avalie algo numa escala descrita, com níveis ordenados. Devolve um valor ponderado por probabilidade, a legenda e a confiança. É o que você usa para graduar intensidade.
3. **Noul**: uma avaliação booleana calibrada. Devolve um valor entre 0 e 1, que é a probabilidade de a condição ser verdadeira. É o que você usa para "isso demonstra impacto real, sim ou não".

Um detalhe que importa muito para engenharia: várias perguntas podem ir num único request e são avaliadas em paralelo, sem que uma enxergue a resposta da outra. Isso torna barato fazer perguntas especulativas e deixar o código decidir depois quais respostas usar.

Um ponto de honestidade que o próprio TypeSafe deixa claro, e que eu respeito no design: a confiança do Choice e do Score resume a concentração da distribuição, não é uma garantia de correção nem uma permissão para agir. Um Noul perto de 0,5 significa probabilidade parecida entre sim e não, não uma intensidade média. Saída tipada garante a interface, não a verdade. Você ainda precisa validar o desempenho do modelo no seu domínio. Guardei isso como regra de ouro na integração.

---

## Parte 2: o que é o NeuroSploit

O NeuroSploit é um harness de pentest autônomo e multi-modelo, escrito em Rust, com console web opcional. Ele recebe um alvo, faz recon, seleciona agentes de ataque, explora, valida e gera relatório. A diferença dele para um scanner comum está na obsessão por prova.

Alguns princípios que definem o projeto, e que são o pano de fundo para entender por que o TypeSafe encaixa tão bem:

- **Sem prova, sem finding.** A regra é dura: nenhuma afirmação sem um recibo, ou seja, evidência real e não paráfrase. Uma resposta HTTP gravada, uma execução observada, um callback recebido.
- **Validadores determinísticos por CWE.** São 27 validadores escritos em Rust que julgam a evidência gravada sem consultar nenhum modelo. Mesma evidência, mesmo veredito, sempre. A skill em Markdown levanta a hipótese, o validador determinístico confirma ou derruba.
- **CVSS calibrado por evidência.** O número sai da equação oficial do FIRST na versão 3.1, e cada métrica de impacto precisa apontar para um recibo. SQL injection que alcançou o interpretador mas não extraiu nada não vira 9.8. Ele registra o score demonstrado separado do potencial.
- **Escopo aplicado em código.** O escopo não é texto de prompt pedindo educadamente para o modelo não sair da linha. É uma fronteira verificada antes de cada request. Alvo fora do capability token é recusado antes do recon, com saída não zero.
- **Trilha de auditoria encadeada por hash, com âncoras externas.** Toda decisão de allow e deny entra numa cadeia que detecta truncamento e reconstrução silenciosa.

Ou seja, o NeuroSploit já era construído em torno de decisão baseada em evidência. Faltava uma camada de julgamento calibrado que operasse sobre essa evidência sem inventar nada. Foi exatamente aí que o TypeSafe entrou.

---

## Parte 3: onde o System One faz sentido dentro de um harness ofensivo

Antes de configurar, vale entender o desenho. Eu não uso o TypeSafe como agente de LLM, porque ele não gera texto nem chama ferramentas, logo não faz recon nem escreve exploit. Eu uso o TypeSafe como o cérebro de decisão de quatro momentos onde o harness precisava de um número e vinha recebendo um parágrafo:

1. **Adjudicação de finding.** Para cada finding, um Choice calibrado entre confirmado, precisa de revisão e rejeitado, avaliado sobre a evidência estruturada e não sobre a narrativa do agente. Junto, um Noul sobre se o impacto real foi demonstrado.
2. **Recalibração de CVSS.** Quando o Noul de impacto fica baixo, o CVSS é regraduado sem os recibos de impacto que não se sustentam, puxando o número para o que a evidência realmente mostra.
3. **Poda de agentes.** Depois que o LLM seleciona os agentes, um request em lote com um Noul por agente pergunta se cada um é relevante para a superfície observada, e os claramente irrelevantes caem. Nunca poda até zero.
4. **Loop de confirmação adicional.** Para classes enumeráveis (XSS, SQLi, redirect, traversal, SSRF, IDOR), um loop de código escolhe o próximo payload com um Choice, dispara pelo motor de replay, e julga a resposta com um Noul, até confirmar ou esgotar.

A regra de ouro em todos os quatro: a camada é aditiva. Um validador determinístico ainda manda. O TypeSafe só consegue baixar confiança ou marcar para revisão. Ele nunca ressuscita um finding rejeitado. Essa decisão de projeto é o que torna a integração segura de ligar e desligar.

---

## Parte 4: como configurar o TypeSafe no NeuroSploit, na prática

Esta é a parte que você veio buscar. É direto.

### Passo 1: obtenha a chave

Crie uma conta no TypeSafe e gere uma chave de API. Ela é um segredo e nunca deve entrar em log, commit ou relatório.

### Passo 2: exporte a chave no ambiente

```bash
export TYPESAFE_API_KEY="sua_chave_aqui"
```

O NeuroSploit lê a chave apenas do ambiente. Se a variável não estiver setada, o harness simplesmente ignora o TypeSafe e roda igual a antes. Isso é proposital.

### Passo 3: escolha o modo com a flag

```bash
# auto (padrão): liga se a chave estiver setada
neurosploit run https://alvo --typesafe auto

# on: força ligado (calibração, regrade de CVSS, poda de agentes, loop de confirmação)
neurosploit run https://alvo --typesafe on

# off: roda o pipeline idêntico, sem TypeSafe (perfeito para comparar)
neurosploit run https://alvo --typesafe off
```

Você também pode controlar por variável de ambiente, útil em automações:

```bash
NEUROSPLOIT_TYPESAFE=off neurosploit run https://alvo --subscription --model anthropic:claude-opus-4-8
```

### Passo 4: confirme que ligou

Durante o run, o feed mostra as linhas do System One, por exemplo a adjudicação de findings, a poda de agentes e o refinamento de confiança. Ao final, cada run grava no `meta.json` o campo `"typesafe": true` ou `false`. Esse campo é o que torna um par com e sem uma medição limpa, porque você consegue provar depois qual run usou a camada.

### O que acontece por baixo

O NeuroSploit fala com o endpoint do System One assim, de forma simplificada:

```
POST https://api.typesafe.ai/v1/systemone
Authorization: Bearer <TYPESAFE_API_KEY>
Content-Type: application/json

{
  "model": "jev-latest",
  "state": { "evidencia": "...request e response gravados..." },
  "questions": {
    "verdict": { "type": "choice", "instructions": "A evidência demonstra a classe?",
      "criteria": { "confirmed": "prova além de dúvida", "needs-review": "plausível mas incompleto", "rejected": "não sustenta" } },
    "impact_demonstrated": { "type": "noul", "instructions": "Houve impacto real?",
      "criteria": { "true": "impacto concreto mostrado", "false": "só um mecanismo ou reflexão" } }
  }
}
```

O harness recebe as probabilidades calibradas e usa esses números para decidir, sem interpretar texto. Simples e determinístico do lado do consumidor.

---

## Parte 5: o benchmark, passo a passo

Agora vem o teste. A regra que estabeleci foi rígida por um motivo: eu queria medir o que o harness mais o LLM realmente encontram, não uma automação pré-programada. Nada de soluções pré-definidas, nada de solver que já sabe as respostas. O LLM descobre e confirma tudo ao vivo.

### Montagem

- **Alvo:** uma aplicação web deliberadamente vulnerável rodando em localhost, com 13 vulnerabilidades semeadas como verdade de campo. IDOR e BOLA, cinco variações de SQL injection, quatro de XSS, open redirect e CRLF.
- **Modelo:** claude-opus-4-8, via assinatura, o mesmo nos dois lados.
- **Configuração:** black-box, recon intensidade 2, voto de um modelo, no máximo 15 agentes. Idêntica nos dois runs.
- **Única diferença:** a flag `--typesafe`.

### Run A, sem TypeSafe

```bash
NEUROSPLOIT_TYPESAFE=off neurosploit run http://localhost:3000 \
  --subscription --model anthropic:claude-opus-4-8 \
  --typesafe off --recon 2 --max-agents 15 --vote-n 1 --focus "<13 endpoints>" -v
```

Resultado: 16 findings, 10 dos 13 alvos, cinco Criticals, 32 minutos e 12 segundos.

### Run B, com TypeSafe

```bash
export TYPESAFE_API_KEY="..."
NEUROSPLOIT_TYPESAFE=on neurosploit run http://localhost:3000 \
  --subscription --model anthropic:claude-opus-4-8 \
  --typesafe on --recon 2 --max-agents 15 --vote-n 1 --focus "<13 endpoints>" -v
```

Resultado: 18 findings, 9 dos 13 alvos, dois Criticals, 26 minutos e 53 segundos, com 9 findings recalibrados.

### A tabela lado a lado

| Métrica | A, sem TypeSafe | B, com TypeSafe |
|---|---|---|
| Alvos acertados | 10 de 13 | 9 de 13 |
| Findings reportados | 16 | 18 |
| Achados além dos 13 alvos | 6 | 9, sendo 2 reais |
| Tempo de parede | 32m12s | 26m53s |
| Criticals reportados | 5 | 2, recalibrados |
| Custo de modelo | zero, assinatura | zero mais TypeSafe, bem abaixo de 5 dólares |

A cobertura das duas execuções somadas foi de 11 dos 13. Nenhum dos dois alcançou o SQL injection de segunda ordem nem o CRLF, que exigem uma cadeia de vários passos que o voto único não perseguiu.

---

## Parte 6: lendo os resultados com honestidade

Se você olhar só o recall, 10 contra 9, é empate dentro do ruído. Essa é a primeira lição e a mais importante: o TypeSafe não é um multiplicador de recall. Ele é uma camada de julgamento. Quem procura mais bugs é o LLM. O que o TypeSafe faz é decidir melhor sobre o que já foi encontrado.

O que o run com TypeSafe entregou de fato:

1. **Dois findings reais que o run sem TypeSafe não reportou:** uma exposição de chave de API em um `config.json` (CWE-200) e um endpoint de login sem bloqueio após tentativas repetidas (CWE-307). Além disso, ele pegou um IDOR de fatura que o outro run perdeu.
2. **Mais rápido, por cerca de cinco minutos**, e com a distribuição de severidade recalibrada.
3. **Nove findings tiveram a confiança refinada**, e o efeito mais visível foi o desmonte de Criticals inflados por classe.

A distribuição de severidade conta a história com clareza. O run sem TypeSafe empilhou cinco Criticals. O run com TypeSafe manteve dois e empurrou o resto para onde a evidência de impacto demonstrado realmente colocava.

E aqui está o gume honesto do experimento, que eu faço questão de contar. O mesmo BOLA em `GET /api/v2/users/:id`, onde um token de cliente lê o registro completo de qualquer usuário, incluindo a senha em texto puro do admin, foi avaliado como Critical 9.1 pelo run sem TypeSafe e como Low pelo run com TypeSafe.

Por que a recalibração puxou para baixo? A lógica é esta: a severidade é graduada a partir do campo de evidência estruturada, ou seja, o par request e response gravado, e não a partir da prosa do agente. Esse finding provou o vazamento na narrativa e no ledger de claims, mas deixou o campo de evidência estruturada vazio. Sem um recibo legível por máquina para a métrica de confidencialidade, tanto o graduador determinístico quanto o Noul de impacto do TypeSafe trataram o impacto como não demonstrado, derrubaram as métricas de impacto para nenhum, e o 9.1 colapsou para Low. A prova existia. Ela só não estava no campo que o graduador lê.

Isso não é um defeito do TypeSafe. É a camada fazendo exatamente o que deve, de forma conservadora. Calibração é um dial na direção da defensabilidade, não um oráculo de correção. A correção certa não é afrouxar o graduador, é fazer os agentes preencherem o campo de evidência estruturada para impacto. O operador continua dono da severidade final.

---

## Parte 7: o refinamento que o benchmark forçou

Um benchmark bem feito acha bug no próprio harness, e este achou. Numa primeira tentativa do run com TypeSafe, a execução colapsou para zero findings no meio do caminho. A causa não era o TypeSafe. A assinatura do modelo bateu no limite de sessão, e o CLI reportou isso como uma resposta normal, com código de saída zero, uma frase do tipo "você atingiu seu limite de sessão". O NeuroSploit tratou aquilo como se fosse uma resposta legítima do modelo, e queimou todos os agentes restantes contra uma sessão morta em vez de pausar.

O conserto foi pontual e importante: agora o sentinela de limite de sessão é detectado mesmo com código de saída zero e é tratado como exaustão, o que faz o harness parquear o run para continuação em vez de desperdiçar agentes. Esse já era o caminho de pausa por cota que existia, só que esse caso específico nunca o alcançava. O benchmark expôs, o código corrigiu.

Um segundo refinamento nasceu da recalibração do BOLA. Se a evidência estruturada estar vazia fazia um finding crítico ser subavaliado, a resposta correta tinha duas frentes, e implementei as duas. A primeira: um passo de salvamento que, quando o campo de evidência estruturada está vazio mas o agente registrou a prova em texto, copia essa prova para o campo estruturado que o graduador lê, sem inventar nada, apenas transportando o que já estava escrito. A segunda, e mais interessante para segurança: ensinar tanto o graduador quanto o TypeSafe a considerar o tipo de dado como um recibo de impacto por si só. Agora existe uma classificação de dado (nenhum, dado comum, dado sensível) que varre a evidência em qualquer campo em busca de assinatura de credencial, chave, token, dado pessoal ou dado de pagamento. Se um dump de credencial foi demonstrado, a métrica de confidencialidade é concedida mesmo com recibo fino, e a recalibração do TypeSafe não derruba a severidade. Em paralelo, a adjudicação passou a fazer uma pergunta Score ao Jev especificamente sobre a sensibilidade do dado exposto, com níveis descritos que vão de conteúdo público a segredos como senha, chave de API e dado de pagamento. Ou seja, o impacto deixou de depender de um único slot binário e passou a considerar, também, a natureza daquilo que vazou. Com isso, o mesmo BOLA do benchmark deixa de colapsar para Low: o tipo de dado, credencial em texto puro, sustenta a gravidade mesmo quando o recibo estruturado veio pobre.

---

## Parte 8: o que dá para fazer com o TypeSafe olhando para segurança ofensiva

O caso do NeuroSploit é uma amostra. O padrão do System One, que é decisão calibrada e tipada em cima de um estado, abre um leque grande para segurança ofensiva. Alguns usos que fazem sentido imediato:

- **Triagem de findings em escala.** Em vez de um humano ou de um LLM verboso classificar centenas de achados, um Choice calibrado separa confirmado de precisa de revisão de rejeitado, com probabilidade, e o código roteia a partir daí.
- **Roteamento de payloads e de próximos passos.** Quando o conjunto de ações candidatas é enumerável, um Choice escolhe a próxima jogada dado o estado atual, e o código executa. Foi assim que montei o loop de confirmação.
- **Verificação de reflexão real.** Um Noul responde se um marcador refletido está numa posição executável ou apenas escapado, separando XSS de verdade de eco inofensivo.
- **Ranqueamento de relevância.** Antes de gastar orçamento de modelo, um Noul por candidato diz se aquela superfície plausivelmente tem aquela classe, podando ruído.
- **Graduação de severidade e de exposição.** Um Score sobre níveis descritos posiciona o impacto sem chutar um número.
- **Detecção de injeção de prompt em conteúdo externo.** Um Noul sobre a resposta do alvo sinaliza tentativa de manipulação, antes de o conteúdo influenciar o planejamento.

O ponto comum de todos esses usos é que eles substituem o julgamento do LLM, não a geração nem a execução. O código continua dono do fluxo. O modelo entrega o senso comum programável onde o código sozinho não tem entendimento semântico. E como as saídas são calibradas e baratas, você pode espalhar decisões pelo pipeline sem estourar custo nem latência.

---

## Conclusão

A conta final é sóbria e, por isso mesmo, confiável. Contra um alvo, em amostra única, o TypeSafe não aumentou o número de bugs encontrados de forma significativa. O que ele fez foi tornar o resultado mais defensável: cortou Criticals inflados por classe, trouxe dois findings reais a mais, rodou mais rápido e recalibrou a confiança de nove findings, tudo sem nunca ressuscitar um achado rejeitado. Ele também expôs, de quebra, dois refinamentos necessários no próprio harness: o campo de evidência estruturada precisa ser preenchido para impacto, e o limite de sessão precisava pausar o run em vez de queimá-lo.

Segurança ofensiva séria não se mede só por quantos bugs você acha. Se mede também por quantos você consegue defender diante do time de compliance e do jurídico do cliente. É nessa segunda métrica que a decisão calibrada do System One entra, e é por isso que ela merece um lugar no pipeline.

O melhor de tudo: é uma flag. Você liga com `--typesafe on`, desliga com `--typesafe off`, e o `meta.json` guarda qual modo rodou. Ou seja, você não precisa acreditar em mim. Rode o par no seu alvo e meça.

Agora a gente manda bala.

---

*NeuroSploit é um harness de pentest autônomo em Rust. O benchmark completo, com os artefatos dos dois runs, o scorer e o relatório visual, está publicado no repositório em `benchmarks/typesafe-2026-09-20`. TypeSafe, System One e Jev são do TypeSafe AI. Teste sempre apenas alvos que você tem autorização para testar.*
