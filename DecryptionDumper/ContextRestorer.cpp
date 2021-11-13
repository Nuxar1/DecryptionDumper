#include "ContextRestorer.h"
#include "Debugger.h"

ContextRestorer::ContextRestorer(Debugger* dbg) : debugger(dbg)
{
	original = debugger->GetContext();
}

ContextRestorer::~ContextRestorer()
{
	debugger->SetContext(&original);
}
