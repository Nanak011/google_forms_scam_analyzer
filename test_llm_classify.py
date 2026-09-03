from app.llm import classify_form

print("=== Scammy example ===")
result = classify_form(
    title="You've won a $500 gift card!",
    description="Click here to claim your prize before it expires tonight",
    questions=["Full name", "Bank account number", "SSN"],
)
print(result.model_dump_json(indent=2))

print("\n=== Legit example ===")
result = classify_form(
    title="CS301 Course Feedback Survey",
    description="Please share your thoughts on this semester's course",
    questions=["What did you like about the course?", "Any suggestions for improvement?"],
)
print(result.model_dump_json(indent=2))