from app.llm import judge_entity_relevance

print("=== False positive case (what happened with 'HCI') ===")
result = judge_entity_relevance(
    "Human-Computer Interaction (HCI)",
    [
        "Report Fraud - Overview - Tax fraud and scams - Identity theft...",
        "HCI is a field of study focused on the design of computer technology.",
    ],
)
print(result)

print("\n=== Genuine case ===")
result = judge_entity_relevance(
    "Acme Bank Support",
    [
        "Acme Bank Support has been reported by dozens of users as a scam impersonating a real bank to steal account credentials.",
        "Complaint: Acme Bank Support called asking for my PIN, this is fraud.",
    ],
)
print(result)