from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException
)

from backend.attack_engine.parser import (
    parse_file
)

router = APIRouter()


@router.post("/topology/upload")
async def upload_topology(
    file: UploadFile = File(...)
):

    try:

        content = await file.read()

        network = parse_file(
            file.filename,
            content
        )

        return {
            "network": {
                "nodes": [
                    n.model_dump()
                    for n in network.nodes
                ],
                "edges": [
                    e.model_dump()
                    for e in network.edges
                ]
            }
        }

    except Exception as e:

        print(
            "UPLOAD ERROR:",
            str(e)
        )

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
