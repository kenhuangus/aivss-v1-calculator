"""Render the specification figures in docs/assets/figures/src to PNG.

Each HTML source draws its connectors after layout and sets
body[data-ready="1"]; the #fig element is captured at 2x scale.
"""
import asyncio
import pathlib
import sys

from playwright.async_api import async_playwright

SRC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "assets" / "figures" / "src"


async def render(files):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 760, "height": 1000}, device_scale_factor=2)
        for f in files:
            await page.goto(f.resolve().as_uri())
            await page.wait_for_selector('body[data-ready="1"]', timeout=15000)
            out = f.parent.parent / (f.stem + ".png")
            await (await page.query_selector("#fig")).screenshot(path=str(out))
            root = SRC.parents[3]
            print(out.relative_to(root) if out.is_relative_to(root) else out)
        await browser.close()


if __name__ == "__main__":
    targets = [pathlib.Path(a) for a in sys.argv[1:]] or sorted(SRC.glob("fig*.html"))
    asyncio.run(render(targets))
