#!/usr/bin/python3 -I
"""Mock llama-server for the llm-local tests: mock_server.py PORTFILE LOGFILE MODEFILE
Binds 127.0.0.1 on a free port (written to PORTFILE), logs each POST body as one JSON line to LOGFILE.
The mode (MODEFILE content, re-read per request): ok | lazy | badjson | http400 | slow | loading | leaky | translate(-once)
  detection requests (response_format json_schema; --strict when the schema has "people"): 'ok'/'leaky' = a good
  detector whose private-passage quotes are deliberately imperfect (a key phrase only, with the chat prefix,
  lower-cased without punctuation, a whole message with a harmless second sentence) and that also reports false
  positives (weekday, time, amount, a venue, harmless messages as private) to exercise llm-local's locating, guards
  and per-sentence check; check requests (schema with only "category"): keyword -> category, else "none"; 'lazy' = people only, no identifiers and no private passages (the
  regex safety pass must catch the identifiers).
  summary requests: a canned summary (aliases for --strict); 'leaky' adds a real surname and a phone number that
  must be scrubbed.
  paraphrase requests (schema {"p": [...]}, policy v4): "Says: " + the item's words with digits, brackets or a capital
  letter; 'hallucinate' turns 07:30 into 08:30 (or adds "on Monday"), also in the retry; 'hallucinate-once' only in the
  first call; 'dropph' drops the [placeholders]; 'leakemail' appends an e-mail address (the regex net must mask it)."""
import sys; sys.dont_write_bytecode = True
import json, os, re, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "fixtures"))
import render  # noqa: E402

CARD = render.VALUES["{{TEST_CARD}}"]
PEOPLE = [("Marco Keller", ["Marco"]), ("Lena Brunner", ["Lena"]), ("Jonas Weber", ["Jonas"]), ("Ali Demir", ["Ali"]),
          ("Sophie", []), ("Herr Huber", ["Herrn Huber"]), ("Dr. Frei", []), ("Nico", []),
          ("Frau Gerold", [])]                      # false positive: the venue "Frau Gerolds Garten"
PII = [("+41 79 123 45 67", "phone"), ("078 765 43 21", "phone"), ("+41 76 555 12 34", "phone"),
       ("CH93 0076 2011 6238 5295 7", "iban"), ("756.1234.5678.97", "ahv"), (CARD, "card"),
       ("lena.brunner92@gmail.com", "email"), ("Seefeldstrasse 112, 8008 Zürich", "address"),
       ("18.10.1996", "birthdate"), ("ZH 123 456", "plate"),
       ("https://drive.google.com/drive/folders/1Qz8xK3vT9mPa2LwR7bN4cYd6E?usp=sharing", "link"),
       # false positives llm-local must ignore:
       ("Samstig", "location"), ("17:30", "id"), ("23.50", "address"), ("Frau Gerolds Garten", "location"),
       ("Mittwuch Abig", "location")]
IDENT = [(t, ty) for t, ty in PII if ty not in ("address", "location")] + [("Samstig", "secret")]
# (quote as the model gives it, category, about): quotes test exact, fuzzy and sentence-widening lookups
PRIVATE = [("Diabetes Typ 1 diagnostiziert", "health", ""),                                     # key phrase only
           ("Jonas Weber: Ich muss euch was sagen: Sarah hat gestern nach vier Jahren mit mir Schluss gemacht, sie "
            "hat mich mit ihrem Arbeitskollegen betrogen.", "relationship", ""),                  # with chat prefix
           ("btw I had a Tinder date on Friday and we ended up spending the night at her place 😏 Anyway, see you all "
            "at the party!", "dating", ""),                                      # whole message: the check splits it
           ("Ich ha e Torte bi de Confiserie Sprüngli bstellt, Abholig am Samstig am 17:30", "relationship", ""),
           ("Leute ich han mini Schlüssel verlore 😭", "confidential", ""),        # false positives: the check says none
           ("unter üs de tobias vom gym het über 9000 schulde und s betreibigsamt isch scho hinder ihm her",
            "money", "Tobias"),                                                                  # case/punctuation
           ("honestly I've been struggling with anxiety and panic attacks lately, I started therapy two weeks ago.",
            "mental_health", ""),
           ("19:00", "health", "")]                                                              # false positive
# the per-sentence check (schema with only "category"): keyword -> category, everything else "none"
CHECK = [(r"Diabetes|Insulin|Arzt", "health"), (r"Schluss gemacht|betrogen", "relationship"),
         (r"Tinder|spending the night", "dating"), (r"Schulde|Betreibigsamt", "money"),
         (r"anxiety|panic|therapy", "mental_health")]
# policy v3: fixtures/money.txt, the owner's investment, salary, bulk purchase and a business deal
# (quoted only when the chunk is that fixture), plus a false positive (a bill due date) the check must reject
MONEY_PRIVATE = [("Ich investiere ab November in drei Tranchen à 25'000 Euro in einen MSCI-World-ETF.", "money", ""),
                 ("min Lohn gaht ab Januar uf 11'200 im Monet ufe", "money", ""),                 # key phrase
                 ("I just bought 40 Pokémon booster boxes in bulk for CHF 6'400 to resell them.", "business", ""),
                 ("Mir händ de Deal mit de Garage Meier abgschlosse, si zahled eus 18'000 für d'Website.", "business",
                  ""),
                 ("Die Swisscom-Rechnung ist am 30.10. fällig", "money", "")]                    # false positive
# the check for the v3 money/business categories; with the admin prompt (--keep-own-money, no "- business:" rule)
# the owner's own money is not private any more, so these say "none" there
CHECK_MONEY = [(r"Tranchen|Lohn", "money"), (r"booster|Deal mit", "business")]
MONEY_SUMMARY = ("- You plan an investment (details private) and mentioned a salary of 11'200 from January.\n"
                 "- Bouldering Wednesday 19:00 at Minimum; team meeting Tuesday 21.10. 14:00; train to Lugano "
                 "Saturday 25.10. 08:32.\n- The Swisscom bill is due 30.10. Marco: 18.- for the cinema.")
SUMMARY = ("- Party for Sophie on Saturday 18.10. at 19:00; You bring the speaker and pick up the cake at 17:30.\n"
           "- Gift: 35.- each for headphones. Ski weekend Laax 16.–18.1.2027, answer by Friday 17.10. 12:00.\n"
           "- Football Thursday 16.10. 19:00 Juchhof. Festival tickets 89.- each. Jonas owed 23.50 for pizza.\n"
           "- Lena shared something private (health).")
SUMMARY_STRICT = SUMMARY.replace("Sophie", "Person E").replace("Jonas", "Person D").replace("Lena", "Person B")


NEG = set("nid nöd nüd ned nit nöt nööd nicht nichts nix nüt nüüt nie niemals nümm nümme nüme nöme niemer niemert "
          "niemand kei keis keini kein keine keinen keinem keiner keins kän käs not never none nobody nothing "
          "nowhere neither nor cannot pas jamais rien aucun aucune non no".split())    # = llm-local's _NEG (+ "no")


def mode(path):
    try:
        return open(path).read().strip() or "ok"
    except OSError:
        return "ok"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        m = mode(self.server.modefile)
        if self.path == "/health":
            return self.send(503, {"error": {"message": "Loading model"}}) if m == "loading" else self.send(200, {"status": "ok"})
        if self.path == "/props":
            return self.send(200, {"default_generation_settings": {"n_ctx": int(os.environ.get("MOCK_CTX", "32768"))}})
        self.send(404, {"error": {"message": "not found"}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        with open(self.server.logfile, "a") as f:
            f.write(json.dumps({"path": self.path, "body": body}, ensure_ascii=False) + "\n")
        m = mode(self.server.modefile)
        if self.path == "/tokenize":
            return self.send(200, {"tokens": list(range(len(body.get("content", "")) // 4))})
        if self.path != "/v1/chat/completions":
            return self.send(404, {"error": {"message": "not found"}})
        if m == "http400":
            return self.send(400, {"error": {"code": 400, "message": "the request exceeds the available context size, try increasing it", "type": "exceed_context_size_error"}})
        if m == "slow":
            time.sleep(5)
        rf = body.get("response_format") or {}
        msgs = body.get("messages", [])
        user = msgs[-1]["content"] if msgs else ""
        props = list((((rf.get("json_schema") or {}).get("schema") or {}).get("properties") or {}))
        if rf.get("type") == "json_schema" and props == ["p"]:             # --paraphrase (policy v4)
            items = re.findall(r"(?m)^\[(\d+)\] (.*)$", user.split("<<<", 1)[-1].rsplit(">>>", 1)[0])
            retry = "changed facts" in user
            outs = []
            for _n, t in items:
                keep = [w for w in re.findall(r"\[[^\]]*\]|[^\s\[]+", t)
                        if re.search(r"\d|^\[|^[A-ZÄÖÜ]", w) or w.lower().strip(".,!?:;") in NEG
                        or w.lower().replace("’", "'").strip(".,!?:;").endswith("n't")]   # v4.1: negations
                p = "Says: " + " ".join(keep) if keep else "Says something."
                if m == "swissbad" and "reserviere" in t:      # the two translations of the 13.10 live test
                    p = "Early booking is required."
                elif m == "swissbad" and "4i scho gnueg" in t:
                    p = "We need enough people by the 4th."
                if m in ("translate", "translate-once") and "Lohn wurde" in t and not (retry and m == "translate-once"):
                    p = "My salary increased to [amount] per month, finally!"   # the 14.10 bench translation (#15)
                if m in ("hallucinate", "hallucinate-once") and not (retry and m == "hallucinate-once"):
                    p = re.sub(r"\b07:30\b", "08:30", p) + (" on Monday" if "07:30" not in t else "")
                if m == "dropph":
                    p = re.sub(r"\[[^\]]*\]", "", p)
                if m == "leakemail":
                    p += " write to lena.brunner@example.org"
                outs.append(p)
            content = "not json {" if m == "badjson" else json.dumps({"p": outs}, ensure_ascii=False)
        elif rf.get("type") == "json_schema" and props == ["category"]:
            sent = user.split("Sentence: <<<", 1)[-1]
            cat = next((c for rx, c in CHECK if re.search(rx, sent)), "none")
            if cat == "none" and "- business:" in (msgs[0]["content"] if msgs else ""):
                cat = next((c for rx, c in CHECK_MONEY if re.search(rx, sent)), "none")
            content = "not json {" if m == "badjson" else json.dumps({"category": cat})
        elif rf.get("type") == "json_schema":
            chunk = user.split("<<<", 1)[-1]
            people = [{"name": n, "variants": [v for v in vs if v in chunk]} for n, vs in PEOPLE
                      if n in chunk or any(v in chunk for v in vs) or (n.split()[-1] in chunk)]
            strict = "people" in ((rf.get("json_schema") or {}).get("schema") or {}).get("properties", {})
            low = re.sub(r"[^\w]+", " ", chunk.lower())
            private = [] if m == "lazy" else [
                {"text": t, "category": c, "about": a} for t, c, a in PRIVATE
                if t in chunk or " ".join(re.sub(r"[^\w]+", " ", t.lower()).split()) in " ".join(low.split())]
            if m != "lazy" and "Tranchen" in chunk:
                private += [{"text": t, "category": c, "about": a} for t, c, a in MONEY_PRIVATE]
            if strict:
                pii = [] if m == "lazy" else [{"text": t, "type": ty} for t, ty in PII if t in chunk]
                obj = {"people": people, "pii": pii}
            else:
                obj = {"private": private,
                       "identifiers": [] if m == "lazy" else [{"text": t, "type": ty} for t, ty in IDENT if t in chunk]}
            content = "not json {" if m == "badjson" else json.dumps(obj, ensure_ascii=False)
        elif rf.get("type") == "json_object":
            content = "this is not json" if m == "badjson" else '{"answer": 42, "lang": "de"}'
        elif "detailed summary" in (msgs[0]["content"] if msgs else ""):
            strict = "aliases (Person A" in msgs[0]["content"]
            if "Hardturmstrasse" in user:                    # fixtures/money.txt
                content = MONEY_SUMMARY
            else:
              content = (SUMMARY_STRICT if strict else SUMMARY) + (
                "\n- Marco said call him on +41 79 123 45 67." if strict and m == "leaky" else
                  "\n- Lena Brunner said call her on +41 79 123 45 67." if m == "leaky" else "")
        else:
            sysmsg = msgs[0]["content"] if msgs and msgs[0]["role"] == "system" else ""
            content = "MOCK ANSWER (system=%s): %s" % (sysmsg or "-", user[:60])
            if m == "think":
                content = "<think>\nhmm\n</think>\n\n" + content
        self.send(200, {"choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
                        "timings": {"prompt_n": len(user) // 4, "prompt_per_second": 100.0, "predicted_n": len(content) // 4,
                                    "predicted_per_second": 10.0, "cache_n": 7, "prompt_ms": len(user) * 2.5,
                                    "predicted_ms": len(content) * 25.0}})


def main():
    portfile, logfile, modefile = sys.argv[1:4]
    port = int(os.environ.get("MOCK_PORT", "0"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.logfile, srv.modefile = logfile, modefile
    with open(portfile + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(portfile + ".tmp", portfile)
    srv.serve_forever()


if __name__ == "__main__":
    main()
