from typing import Optional
from pydantic import BaseModel


class SortOptionsDto(BaseModel):
    sort_by: Optional[str]
    sort_dir: Optional[str]
